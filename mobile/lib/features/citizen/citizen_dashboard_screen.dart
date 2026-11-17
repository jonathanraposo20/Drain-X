import 'package:flutter/material.dart';
import '../../core/auth/auth_service.dart';
import '../../core/network/api_client.dart';
import '../../core/theme/app_theme.dart';
import '../../models/incident.dart';
import '../../widgets/incident_card.dart';
import '../../widgets/empty_state_view.dart';
import '../auth/welcome_screen.dart';
import 'citizen_report_screen.dart';
import 'citizen_report_detail_screen.dart';

class CitizenDashboardScreen extends StatefulWidget {
  final String reporterName;
  final ApiClient? apiClient;

  const CitizenDashboardScreen({
    super.key,
    required this.reporterName,
    this.apiClient,
  });

  @override
  State<CitizenDashboardScreen> createState() => _CitizenDashboardScreenState();
}

class _CitizenDashboardScreenState extends State<CitizenDashboardScreen> {
  late final ApiClient _apiClient;
  List<Incident> _incidents = [];
  bool _isLoading = true;
  String? _errorMessage;
  String _activeFilter = 'ALL'; // 'ALL', 'ACTIVE', 'RESOLVED', 'MINE'
  final TextEditingController _searchController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _apiClient = widget.apiClient ?? ApiClient();
    _fetchIncidents();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _fetchIncidents() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final incidents = await _apiClient.getIncidents();
      setState(() {
        _incidents = incidents;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }

  bool get _isAnonymousUser {
    final name = widget.reporterName.trim().toLowerCase();
    return name.isEmpty || name == 'citizen anonymous' || name == 'citizen';
  }

  List<Incident> _getFilteredIncidents() {
    final query = _searchController.text.trim().toLowerCase();

    return _incidents.where((item) {
      // 1. Tab filter
      if (_activeFilter == 'ACTIVE') {
        if (item.status == 'RESOLVED' || item.status == 'REJECTED') {
          return false;
        }
      } else if (_activeFilter == 'RESOLVED') {
        if (item.status != 'RESOLVED') {
          return false;
        }
      } else if (_activeFilter == 'MINE') {
        if (_isAnonymousUser) {
          // Anonymous reports are unlinked to protect privacy; they cannot claim
          // all other anonymous submissions across all citizens as "MINE".
          return false;
        }
        final reporter = widget.reporterName.trim().toLowerCase();
        final itemReporter = (item.reporterName ?? '').trim().toLowerCase();
        if (!itemReporter.contains(reporter)) {
          return false;
        }
      }

      // 2. Search query filter
      if (query.isNotEmpty) {
        final idMatch = item.id.toLowerCase().contains(query);
        final catMatch = item.category.toLowerCase().contains(query);
        final descMatch = item.description.toLowerCase().contains(query);
        if (!idMatch && !catMatch && !descMatch) {
          return false;
        }
      }

      return true;
    }).toList();
  }

  Widget _buildEmptyState() {
    if (_searchController.text.trim().isNotEmpty) {
      return EmptyStateView(
        icon: Icons.search_off_rounded,
        title: 'No Matching Reports',
        description: 'No drainage hazard reports match "${_searchController.text.trim()}". Check your incident reference ID or search term.',
      );
    }
    if (_activeFilter == 'MINE') {
      if (_isAnonymousUser) {
        return const EmptyStateView(
          icon: Icons.lock_outline_rounded,
          title: 'Anonymous Reports Are Unlinked',
          description: 'To protect civic privacy, anonymous incident reports are not attached to a personal account. If you submitted an anonymous report, please search for its tracking reference (e.g. INC-XXXXXXXX) in the search bar above.',
        );
      }
      return EmptyStateView(
        icon: Icons.assignment_outlined,
        title: 'No Submissions Found',
        description: 'You have not submitted any incidents under the name "${widget.reporterName}". You can report a new drainage hazard using the button below.',
      );
    }
    if (_activeFilter == 'ACTIVE') {
      return const EmptyStateView(
        icon: Icons.check_circle_outline,
        title: 'No Active Hazards',
        description: 'There are currently no active drainage blockage or flood hazard incidents reported in the basin.',
      );
    }
    if (_activeFilter == 'RESOLVED') {
      return const EmptyStateView(
        icon: Icons.task_alt_rounded,
        title: 'No Resolved Incidents',
        description: 'No incidents have been marked as resolved yet in this reporting cycle.',
      );
    }
    return const EmptyStateView(
      icon: Icons.check_circle_outline,
      title: 'No Incidents in System',
      description: 'All municipal drainage conduits and culverts are operating within normal capacity.',
    );
  }

  void _showLogoutDialog() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Confirm Citizen Logout'),
        content: const Text('Are you sure you want to end your active reporting session?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFDC2626)),
            onPressed: () {
              Navigator.pop(ctx);
              AuthService().logout();
              Navigator.pushAndRemoveUntil(
                context,
                MaterialPageRoute(builder: (_) => const WelcomeScreen()),
                (route) => false,
              );
            },
            child: const Text('Logout'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final bool hasData = _incidents.isNotEmpty;
    final bool isStale = _errorMessage != null && hasData;

    final activeCount = _incidents.where((i) => i.status != 'RESOLVED' && i.status != 'REJECTED').length;
    final resolvedCount = _incidents.where((i) => i.status == 'RESOLVED').length;
    final assignedCrewCount = _incidents.where((i) =>
        (i.status == 'ASSIGNED' || i.status == 'INVESTIGATING') &&
        (i.assignedTo != null && i.assignedTo!.trim().isNotEmpty)).length;

    final activeDisplay = hasData ? '$activeCount' : (_isLoading ? '...' : '--');
    final crewDisplay = hasData ? '$assignedCrewCount' : (_isLoading ? '...' : '--');
    final resolvedDisplay = hasData ? '$resolvedCount' : (_isLoading ? '...' : '--');

    final filteredIncidents = _getFilteredIncidents();

    return Scaffold(
      appBar: AppBar(
        title: const Text('DRAIN-X Citizen Portal'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh Reports',
            onPressed: _fetchIncidents,
          ),
          IconButton(
            icon: const Icon(Icons.logout),
            tooltip: 'Logout',
            onPressed: _showLogoutDialog,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: const Color(0xFF0284C7),
        icon: const Icon(Icons.add_a_photo_rounded, color: Colors.white),
        label: const Text('Report Hazard', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.white)),
        onPressed: () async {
          final created = await Navigator.push<bool>(
            context,
            MaterialPageRoute(
              builder: (_) => CitizenReportScreen(reporterName: widget.reporterName),
            ),
          );
          if (created == true) {
            _fetchIncidents();
          }
        },
      ),
      body: RefreshIndicator(
        onRefresh: _fetchIncidents,
        child: SingleChildScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Welcome Header Banner
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: const BoxDecoration(
                  color: AppTheme.primaryNavy,
                  borderRadius: BorderRadius.only(
                    bottomLeft: Radius.circular(20),
                    bottomRight: Radius.circular(20),
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'Welcome, ${widget.reporterName.isEmpty ? 'Citizen' : widget.reporterName}',
                                style: const TextStyle(
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                  color: Colors.white,
                                ),
                              ),
                              const SizedBox(height: 2),
                              const Text(
                                'Panaji Municipal Basin • Citizen Flood Sentinel',
                                style: TextStyle(fontSize: 11, color: Color(0xFF94A3B8)),
                              ),
                            ],
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: const Color(0xFF1E293B),
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: const Color(0xFF334155)),
                          ),
                          child: const Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(Icons.shield_outlined, size: 14, color: Color(0xFF38BDF8)),
                              SizedBox(width: 4),
                              Text('LIVE SENTINEL', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF38BDF8))),
                            ],
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Quick KPI Counts
                    Row(
                      children: [
                        Expanded(
                          child: Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E293B),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(color: const Color(0xFF334155)),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text('ACTIVE HAZARDS', style: TextStyle(fontSize: 10, color: Color(0xFF94A3B8), fontWeight: FontWeight.w600)),
                                const SizedBox(height: 4),
                                Text(
                                  activeDisplay,
                                  style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Color(0xFF38BDF8)),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E293B),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(color: const Color(0xFF334155)),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text('CREW ASSIGNED', style: TextStyle(fontSize: 10, color: Color(0xFF94A3B8), fontWeight: FontWeight.w600)),
                                const SizedBox(height: 4),
                                Text(
                                  crewDisplay,
                                  style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Color(0xFFFBBF24)),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1E293B),
                              borderRadius: BorderRadius.circular(10),
                              border: Border.all(color: const Color(0xFF334155)),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text('RESOLVED', style: TextStyle(fontSize: 10, color: Color(0xFF94A3B8), fontWeight: FontWeight.w600)),
                                const SizedBox(height: 4),
                                Text(
                                  resolvedDisplay,
                                  style: const TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: Color(0xFF4ADE80)),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),

              if (isStale)
                Container(
                  margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  decoration: BoxDecoration(
                    color: const Color(0xFFFEF3C7),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: const Color(0xFFFDE68A)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.sync_problem_rounded, size: 18, color: Color(0xFFD97706)),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'Sync warning: ${_errorMessage!}. Showing cached data.',
                          style: const TextStyle(fontSize: 11, color: Color(0xFF92400E)),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.refresh, size: 16, color: Color(0xFFD97706)),
                        onPressed: _fetchIncidents,
                      ),
                    ],
                  ),
                ),

              const SizedBox(height: 16),

              // Search & Filter Section
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Column(
                  children: [
                    // Search Bar
                    TextField(
                      controller: _searchController,
                      onChanged: (_) => setState(() {}),
                      decoration: InputDecoration(
                        hintText: 'Search by ID (INC-XXXX) or description...',
                        prefixIcon: const Icon(Icons.search, size: 20, color: Color(0xFF64748B)),
                        suffixIcon: _searchController.text.isNotEmpty
                            ? IconButton(
                                icon: const Icon(Icons.clear, size: 18),
                                onPressed: () {
                                  _searchController.clear();
                                  setState(() {});
                                },
                              )
                            : null,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                      ),
                      style: const TextStyle(fontSize: 13),
                    ),
                    const SizedBox(height: 10),

                    // Filter Chips Row
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: [
                          _buildFilterChip('ALL', hasData ? 'All Reports (${_incidents.length})' : 'All Reports'),
                          const SizedBox(width: 6),
                          _buildFilterChip('ACTIVE', hasData ? 'Active Hazards ($activeCount)' : 'Active Hazards'),
                          const SizedBox(width: 6),
                          _buildFilterChip('RESOLVED', hasData ? 'Resolved ($resolvedCount)' : 'Resolved'),
                          const SizedBox(width: 6),
                          _buildFilterChip('MINE', 'My Submissions'),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 14),

              // Incident Feed Header
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      'INCIDENT LOG & FEED',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: Color(0xFF475569),
                        letterSpacing: 0.5,
                      ),
                    ),
                    Text(
                      '${filteredIncidents.length} shown',
                      style: const TextStyle(fontSize: 11, color: Color(0xFF64748B), fontWeight: FontWeight.w500),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 8),

              // Incident List or State Views
              if (_isLoading && !hasData)
                const Padding(
                  padding: EdgeInsets.all(40),
                  child: Center(child: CircularProgressIndicator()),
                )
              else if (_errorMessage != null && !hasData)
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFFFEF2F2),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0xFFFECACA)),
                    ),
                    child: Column(
                      children: [
                        const Icon(Icons.error_outline, color: Color(0xFFDC2626), size: 32),
                        const SizedBox(height: 8),
                        Text(
                          _errorMessage!,
                          textAlign: TextAlign.center,
                          style: const TextStyle(fontSize: 12, color: Color(0xFF991B1B)),
                        ),
                        const SizedBox(height: 12),
                        ElevatedButton.icon(
                          icon: const Icon(Icons.refresh, size: 16),
                          onPressed: _fetchIncidents,
                          label: const Text('Retry Connection'),
                        ),
                      ],
                    ),
                  ),
                )
              else if (filteredIncidents.isEmpty)
                _buildEmptyState()
              else
                ListView.builder(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  itemCount: filteredIncidents.length,
                  itemBuilder: (context, index) {
                    final item = filteredIncidents[index];
                    return IncidentCard(
                      incident: item,
                      onTap: () async {
                        await Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (_) => CitizenReportDetailScreen(incidentId: item.id),
                          ),
                        );
                        _fetchIncidents();
                      },
                    );
                  },
                ),

              const SizedBox(height: 80), // Padding for floating action button
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildFilterChip(String key, String label) {
    final isSelected = _activeFilter == key;
    return ChoiceChip(
      label: Text(label),
      labelStyle: TextStyle(
        fontSize: 11,
        fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
        color: isSelected ? Colors.white : const Color(0xFF334155),
      ),
      selected: isSelected,
      selectedColor: const Color(0xFF0284C7),
      backgroundColor: Colors.white,
      side: BorderSide(color: isSelected ? const Color(0xFF0284C7) : const Color(0xFFCBD5E1)),
      onSelected: (val) {
        if (val) {
          setState(() {
            _activeFilter = key;
          });
        }
      },
    );
  }
}
