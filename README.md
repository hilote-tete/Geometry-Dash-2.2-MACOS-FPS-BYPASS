# Geometry-Dash-2.2-MACOS-FPS-BYPASS

# FPS & VSync Scanner for Geometry Dash

This script is designed to find and modify the FPS cap and VSync settings in Geometry Dash 2.2 using Frida. It attaches to the game process, scans memory for FPS and VSync-related values, and allows real-time patching to adjust these settings.

## Features
- Automatically detects Geometry Dash 2.2 process.
- Scans for memory addresses related to FPS cap and VSync.
- Uses Frida to dynamically monitor and analyze memory values.
- Provides an interactive patching option to:
  - Cap FPS at 180.
  - Disable VSync.
- Logs real-time events and errors for debugging.

## How It Works
1. The script lists running processes to find Geometry Dash.
2. Attaches to the process using Frida.
3. Scans memory to identify FPS and VSync values based on expected patterns.
4. Detects and analyzes stability of potential FPS/VSync memory addresses.
5. Offers the option to patch identified memory addresses to modify the FPS cap or disable VSync.

## Installation

Before running the script, install the required dependencies:

```sh
pip install frida colorama
```

Additionally, ensure you have Frida installed on your system:

```sh
pip install frida-tools
```

## Usage

Run the script to start scanning for the Geometry Dash process and analyze FPS/VSync memory values:

```sh
python rt2.py
```

Follow the interactive prompts to patch FPS or VSync settings.

## Logging
All events, warnings, and errors are logged to `fps_vsync_scan.log` which is in the folder the script is located at for debugging purposes.

