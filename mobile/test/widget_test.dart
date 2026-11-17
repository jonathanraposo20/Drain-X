import 'package:flutter_test/flutter_test.dart';
import 'package:drainx_mobile/app/app.dart';

void main() {
  testWidgets('DrainXMobileApp renders welcome screen branding and portal options', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const DrainXMobileApp());
    await tester.pumpAndSettle();

    // Verify that DRAIN-X branding and key portal navigation buttons are rendered.
    expect(find.text('DRAIN-X'), findsOneWidget);
    expect(find.text('Integrated Urban Flood Intelligence'), findsOneWidget);
    expect(find.text('COMPETITION MVP DEMO'), findsOneWidget);
    expect(find.text('CITIZEN PORTAL'), findsOneWidget);
    expect(find.text('MUNICIPAL OPERATIONS'), findsOneWidget);
    expect(find.text('FIELD WORKER PORTAL'), findsOneWidget);
  });
}
