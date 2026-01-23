# Changelog

## [1.3.8] - 2026-01-23
### Added
- **Error Logging System**: Implemented a background logger that captures PHP errors, exceptions, and fatal crashes specifically related to the ADC Security plugin.
- **Improved Debug Export**: The debug report now includes the last 50 error entries to help with technical support and troubleshooting.
- **Log Maintenance**: Added a feature to clear recorded logs from the Support settings tab.

## [1.3.7] - 2026-01-22
### Fixed
- **Custom Login URL**: Improved compatibility with maintenance mode plugins (e.g., Elementor) by loading the login template earlier in the execution cycle.
- **Redirect Logic**: Fixed an issue where the logout redirect would fail or loop back to the home page when using a custom login slug.

## [1.3.6] - 2026-01-13
### Added
- **Security Headers**: Added HSTS (HTTP Strict Transport Security) header enforcement for improved SSL security.
- **Auto-Update System**: Implemented a custom updater class to fetch plugin updates from a remote verified source.
- **Update Controls**: Added comprehensive settings to manage automatic updates for Plugins, Themes, and WordPress Core.
- **Changelog Interface**: Integrated a dedicated tab in settings to view technical changes directly within the dashboard.

### Fixed
- **Login Security**: Implemented a robust fallback mechanism for the Custom Login URL to prevent 404 errors on Nginx/Permalinks environments.
