import 'package:flutter_test/flutter_test.dart';
import 'package:drainx_mobile/app/app.dart';
import 'package:drainx_mobile/features/auth/supabase_login_screen.dart';

void main() {
  testWidgets('welcome screen opens the real Supabase account sign-in form', (
    tester,
  ) async {
    await tester.pumpWidget(const DrainXMobileApp());
    await tester.pumpAndSettle();

    final signInButton = find.text('Sign in with DRAIN-X account');
    await tester.ensureVisible(signInButton);
    await tester.tap(signInButton);
    await tester.pumpAndSettle();

    expect(find.byType(SupabaseLoginScreen), findsOneWidget);
    expect(find.text('Email address'), findsOneWidget);
    expect(find.text('Password'), findsOneWidget);
    expect(find.text('Sign in'), findsOneWidget);
  });
}
