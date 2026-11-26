import 'package:flutter/material.dart';
import 'core/auth/auth_service.dart';
import 'app/app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await AuthService().restoreSession();
  runApp(const DrainXMobileApp());
}
