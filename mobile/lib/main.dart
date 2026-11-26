import 'package:flutter/material.dart';

import 'app/app.dart';
import 'core/auth/auth_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AuthService().initialize();
  runApp(const DrainXMobileApp());
}
