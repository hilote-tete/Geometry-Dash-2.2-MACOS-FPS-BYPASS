import frida
import time
import subprocess
from collections import defaultdict
from colorama import Fore, Style, init
import logging

init(autoreset=True)
logging.basicConfig(
    level=logging.DEBUG,
    format=f'%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fps_vsync_scan.log"),
        logging.StreamHandler()
    ]
)

class FPSVSyncFinder:
    def __init__(self, pid: int):
        self.pid = pid
        self.pattern_occurrences = defaultdict(int)
        self.offset_counts = defaultdict(int)
        self.offset_values = defaultdict(list)
        self.potential_fps_offsets = {}
        self.confidence_scores = {}
        self.session = None
        self.found_target = False
        logging.info(f"Initialized FPSVSyncFinder with PID: {pid}")

    def patch_value(self, addr, value_type):
        if value_type == 'fps':
            new_value = 180.0
            print(f"\n{Fore.YELLOW}Do you want to patch this address to cap FPS at 180? (y/n){Style.RESET_ALL}")
        else:
            new_value = 0.0
            print(f"\n{Fore.YELLOW}Do you want to patch this address to turn VSync OFF? (y/n){Style.RESET_ALL}")
            
        choice = input().lower()
        if choice == 'y':
            patch_script = f"""
            var targetAddr = ptr("{addr}");
            Memory.writeFloat(targetAddr, {new_value});
            send({{type: 'patch_status', message: 'Patch applied successfully'}});
            """
            
            patch_session = self.session.create_script(patch_script)
            patch_session.load()
            print(f"{Fore.GREEN}Successfully patched {value_type} value to {new_value}{Style.RESET_ALL}")
            return True
        return False

    def start_real_time_analysis(self):
        logging.info("Starting real-time analysis thread...")
        try:
            logging.debug("Attempting to attach to process...")
            self.session = frida.attach(self.pid)
            logging.info("Successfully attached to process")
            
            logging.debug("Creating Frida script...")
            script = self.session.create_script(self.get_frida_script())
            logging.info("Frida script created")
            
            logging.debug("Setting up message handler...")
            script.on('message', self.on_message)
            logging.info("Message handler set up")
            
            logging.debug("Loading script...")
            script.load()
            logging.info("Script loaded successfully")

            print(f"{Fore.GREEN}Analysis started successfully. Press Ctrl+C to stop.{Style.RESET_ALL}")
            
            try:
                while not self.found_target:
                    time.sleep(1)
                    self.analyze_patterns()
                    logging.debug("Analysis cycle completed")
            except KeyboardInterrupt:
                logging.info("Received keyboard interrupt")
                print(f"{Fore.RED}{Style.BRIGHT}Exiting real-time analysis...{Style.RESET_ALL}")
                
        except frida.ProcessNotFoundError:
            logging.error(f"Process with PID {self.pid} not found!")
            print(f"{Fore.RED}Error: Process not found. Make sure Geometry Dash is running.{Style.RESET_ALL}")
        except frida.ServerNotRunningError:
            logging.error("Frida server is not running!")
            print(f"{Fore.RED}Error: Frida server is not running. Please ensure Frida is properly installed.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}", exc_info=True)
            print(f"{Fore.RED}An unexpected error occurred: {str(e)}{Style.RESET_ALL}")

    def get_frida_script(self):
        logging.debug("Generating Frida script")
        script = """
        try {
            send({type: 'status', message: 'Script initialization started'});
            
            var baseAddr = Process.enumerateModules()[0].base;
            var moduleSize = Process.enumerateModules()[0].size;
            
            send({
                type: 'status',
                message: 'Module info retrieved',
                baseAddr: baseAddr.toString(),
                moduleSize: moduleSize
            });
            
            function scanMemoryRange(start, size) {
                send({type: 'status', message: 'Starting memory scan'});
                var current = start;
                var end = start.add(size);
                var valuesFound = 0;
                
                while (current.compare(end) < 0) {
                    try {
                        var value = Memory.readFloat(current);
                        if (value !== 0 && ((value >= 59.9 && value <= 60.1) || value === 1)) {
                            var surroundingValues = [];
                            for(var offset = -16; offset <= 16; offset += 4) {
                                try {
                                    var nearbyValue = Memory.readFloat(current.add(offset));
                                    surroundingValues.push(nearbyValue);
                                } catch(e) {
                                    surroundingValues.push(null);
                                }
                            }
                            
                            valuesFound++;
                            send({
                                type: 'value_found',
                                address: current,
                                value: value,
                                surrounding: surroundingValues,
                                usage_count: 0
                            });
                        }
                    } catch (e) {}
                    current = current.add(4);
                }
                
                send({
                    type: 'status',
                    message: 'Scan completed',
                    valuesFound: valuesFound
                });
            }

            setInterval(function() {
                scanMemoryRange(baseAddr, moduleSize);
            }, 500);
            
            send({type: 'status', message: 'Script initialization completed'});
            
        } catch (e) {
            send({type: 'error', message: e.toString()});
        }
        """
        logging.debug("Frida script generated")
        return script

    def analyze_patterns(self):
        logging.debug("Starting pattern analysis")
        for addr, values in self.offset_values.items():
            if len(values) < 5:
                continue
                
            fps_confidence = 0
            vsync_confidence = 0
            
            avg_value = sum(values) / len(values)
            value_stability = len(set(values)) == 1
            
            if 59.9 <= avg_value <= 60.1:
                fps_confidence += 40
                if value_stability:
                    fps_confidence += 30
                logging.debug(f"Found potential FPS value at {addr}: {avg_value}")
            elif avg_value in (0, 1):
                vsync_confidence += 40
                if value_stability:
                    vsync_confidence += 30
                logging.debug(f"Found potential VSync value at {addr}: {avg_value}")
                
            if fps_confidence >= 70 or vsync_confidence >= 70:
                value_type = 'fps' if fps_confidence >= 70 else 'vsync'
                confidence = fps_confidence if value_type == 'fps' else vsync_confidence
                
                print(f"\n{Fore.GREEN}High confidence {value_type.upper()} value found!{Style.RESET_ALL}")
                print(f"Address: {addr}")
                print(f"Current value: {avg_value}")
                print(f"Confidence: {confidence}%")
                print(f"Value stability: {'Stable' if value_stability else 'Varying'}")
                
                if self.patch_value(addr, value_type):
                    self.found_target = True
                    return

    def on_message(self, message, data):
        try:
            if message['type'] == 'send':
                payload = message['payload']
                if payload['type'] == 'value_found':
                    addr = payload['address']
                    value = payload['value']
                    self.offset_values[addr].append(value)
                    logging.debug(f"Value found - Address: {addr}, Value: {value}")
                elif payload['type'] == 'memory_access':
                    addr = payload['address']
                    self.offset_counts[addr] += 1
                    logging.debug(f"Memory access detected at: {addr}")
                elif payload['type'] == 'status':
                    logging.info(f"Frida status: {payload['message']}")
                elif payload['type'] == 'error':
                    logging.error(f"Frida error: {payload['message']}")
        except Exception as e:
            logging.error(f"Error in message handler: {str(e)}", exc_info=True)

def list_geometry_dash_processes():
    print(r"""
  _      _   _           _            
 | |    | \ | |         | |           
 | |    |  \| | __ _  __| | _____   __
 | |    | . ` |/ _` |/ _` |/ _ \ \ / /
 | |____| |\  | (_| | (_| |  __/\ V / 
 |______|_| \_|\__,_|\__,_|\___| \_/  
""")
    logging.info("Searching for Geometry Dash processes")
    print(f"{Fore.CYAN}Looking for Geometry Dash 2.2 process...{Style.RESET_ALL}")
    try:
        ps_output = subprocess.check_output(["ps", "aux"]).decode("utf-8")
        processes = []
        for line in ps_output.splitlines():
            if "geometrydash" in line.lower() or "geometry dash" in line.lower():
                parts = line.split()
                pid = parts[1]
                process_name = " ".join(parts[10:])
                processes.append((pid, process_name))
                logging.debug(f"Found process - PID: {pid}, Name: {process_name}")
                
        if not processes:
            logging.warning("No Geometry Dash processes found")
            print(f"{Fore.RED}No Geometry Dash processes found.{Style.RESET_ALL}")
            return None
            
        print(f"{Fore.YELLOW}Select a process by number:")
        for idx, (pid, name) in enumerate(processes):
            print(f"{Fore.GREEN}{idx + 1}. PID: {pid} - {name}{Style.RESET_ALL}")
            
        selected_index = int(input(f"{Fore.YELLOW}Enter the number of the process to analyze: ")) - 1
        selected_pid, selected_name = processes[selected_index]
        logging.info(f"Selected process - PID: {selected_pid}, Name: {selected_name}")
        print(f"{Fore.GREEN}Selected PID: {selected_pid} - {selected_name}{Style.RESET_ALL}")
        return int(selected_pid)
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Error listing processes: {str(e)}", exc_info=True)
        print(f"{Fore.RED}Error listing processes: {e}{Style.RESET_ALL}")
        return None

def main():
    logging.info("Starting FPS/VSync finder")
    pid = list_geometry_dash_processes()
    if pid:
        finder = FPSVSyncFinder(pid)
        finder.start_real_time_analysis()

if __name__ == "__main__":
    main()
