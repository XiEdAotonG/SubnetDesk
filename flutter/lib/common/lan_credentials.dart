import 'dart:convert';

/// Protocol version understood by the Rust LAN credential parser
/// (`LanCredentialPayload` in `src/flutter.rs`).
const int lanCredentialProtocolVersion = 1;

/// Builds the `password` argument for a LAN connection.
///
/// [remember] asks the core to persist the credential once the remote device
/// accepts it. The core never reports a stored password back to Dart, so this
/// payload is the only place a password crosses the FFI boundary.
String buildLanPasswordPayload({
  required String username,
  required String password,
  required bool remember,
}) {
  return jsonEncode({
    'lan_version': lanCredentialProtocolVersion,
    'username': username,
    'password': password,
    'remember': remember,
  });
}
