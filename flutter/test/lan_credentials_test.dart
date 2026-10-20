import 'dart:convert';

import 'package:flutter_hbb/common/lan_credentials.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('LAN password payload', () {
    test('carries the remember flag and the plaintext password', () {
      final payload =
          jsonDecode(
                buildLanPasswordPayload(
                  username: 'operator',
                  password: 's3cret',
                  remember: true,
                ),
              )
              as Map<String, dynamic>;

      expect(payload, {
        'lan_version': lanCredentialProtocolVersion,
        'username': 'operator',
        'password': 's3cret',
        'remember': true,
      });
    });

    test('does not persist when the user leaves remember unchecked', () {
      final payload =
          jsonDecode(
                buildLanPasswordPayload(
                  username: 'operator',
                  password: 's3cret',
                  remember: false,
                ),
              )
              as Map<String, dynamic>;

      expect(payload['remember'], isFalse);
      expect(payload['lan_version'], 1);
    });
  });
}
