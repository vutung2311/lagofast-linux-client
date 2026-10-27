#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Building LagoFast NetworkManager Plugin ==="
cd "$ROOT_DIR"
go build -o bin/nm-lagofast-service ./cmd/nm-lagofast-service
go build -o bin/lagofast ./cmd/lagofast

# Build KDE Plasma UI Plugin if tools exist
if command -v /usr/lib/qt6/moc >/dev/null 2>&1 && command -v g++ >/dev/null 2>&1; then
  echo "Building KDE Plasma UI Plugin (plasmanetworkmanagement_lagofastui)..."
  mkdir -p "$ROOT_DIR/plasma-plugin"
  (
    cd "$ROOT_DIR/plasma-plugin"
    /usr/lib/qt6/moc -I/usr/include/qt6 -I/usr/include/qt6/QtCore -I/usr/include/qt6/QtWidgets -I/usr/include/KF6/KCoreAddons -I/usr/include/KF6/NetworkManagerQt -I/usr/include/KF6 lagofast_ui_plugin.cpp -o lagofast_ui_plugin.moc
    g++ -shared -fPIC -O2 lagofast_ui_plugin.cpp \
      -I. \
      -I/usr/include/qt6 -I/usr/include/qt6/QtCore -I/usr/include/qt6/QtWidgets -I/usr/include/qt6/QtGui -I/usr/include/qt6/QtDBus \
      -I/usr/include/KF6 -I/usr/include/KF6/KCoreAddons -I/usr/include/KF6/NetworkManagerQt \
      $(pkg-config --cflags libnm gio-2.0) \
      -lQt6Core -lQt6Widgets -lQt6Gui -lQt6DBus \
      -lKF6CoreAddons -lKF6NetworkManagerQt \
      -lplasmanm_editor \
      -o plasmanetworkmanagement_lagofastui.so
  )
fi

echo "=== Installing to System (using pkexec) ==="
pkexec bash -c "
  mkdir -p /etc/NetworkManager/VPN
  mkdir -p /etc/dbus-1/system.d
  mkdir -p /usr/local/bin

  install -m 755 '$ROOT_DIR/bin/nm-lagofast-service' /usr/local/bin/nm-lagofast-service
  install -m 755 '$ROOT_DIR/bin/lagofast' /usr/local/bin/lagofast
  setcap cap_net_admin,cap_net_raw+eip /usr/local/bin/lagofast || true
  setcap cap_net_admin,cap_net_raw+eip '$ROOT_DIR/bin/lagofast' || true
  install -m 644 '$ROOT_DIR/config/nm-lagofast-service.name' /etc/NetworkManager/VPN/nm-lagofast-service.name
  mkdir -p /usr/lib/NetworkManager/VPN
  install -m 644 '$ROOT_DIR/config/nm-lagofast-service.name' /usr/lib/NetworkManager/VPN/nm-lagofast-service.name
  install -m 644 '$ROOT_DIR/config/org.freedesktop.NetworkManager.lagofast.conf' /etc/dbus-1/system.d/org.freedesktop.NetworkManager.lagofast.conf

  # Install KDE Plasma NM UI Plugin if built
  if [ -f '$ROOT_DIR/plasma-plugin/plasmanetworkmanagement_lagofastui.so' ]; then
    mkdir -p /usr/lib/qt6/plugins/plasma/network/vpn
    install -m 755 '$ROOT_DIR/plasma-plugin/plasmanetworkmanagement_lagofastui.so' /usr/lib/qt6/plugins/plasma/network/vpn/plasmanetworkmanagement_lagofastui.so
  fi

  # Sync session for NetworkManager daemon
  mkdir -p /etc/lagofast
  if [ -f '/home/tung/.config/lagofast/session.json' ]; then
    install -m 644 '/home/tung/.config/lagofast/session.json' /etc/lagofast/session.json
  fi

  # Reload D-Bus and NetworkManager configuration
  if systemctl is-active --quiet dbus; then
    systemctl reload dbus || true
  fi
  if systemctl is-active --quiet NetworkManager; then
    systemctl reload NetworkManager || true
  fi
"

echo "=== Automatically Adding NetworkManager VPN Connection ==="
if nmcli connection show "LagoFast-WWM" >/dev/null 2>&1; then
  echo "Updating existing connection 'LagoFast-WWM'..."
  nmcli connection modify "LagoFast-WWM" vpn.data "game_id=54758" ipv4.never-default yes connection.autoconnect no
else
  echo "Adding connection 'LagoFast-WWM' (Where Winds Meet)..."
  nmcli connection add type vpn vpn-type lagofast con-name "LagoFast-WWM" vpn.data "game_id=54758" ipv4.never-default yes connection.autoconnect no
fi

echo "=== Setup Complete ==="
echo "The LagoFast VPN plugin is registered with NetworkManager."
echo "Connection 'LagoFast-WWM' is now available in your desktop network tray."
echo "You can manage it from the desktop tray icon or via terminal:"
echo "  nmcli connection up 'LagoFast-WWM'"
echo "  nmcli connection down 'LagoFast-WWM'"
