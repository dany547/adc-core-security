# Changelog

## [1.3.6] - 2026-01-13
### Added
- **Security Headers**: Added HSTS (HTTP Strict Transport Security) header enforcement for improved SSL security.
- **Auto-Update System**: Implemented a custom updater class to fetch plugin updates from a remote verified source.
- **Update Controls**: Added comprehensive settings to manage automatic updates for Plugins, Themes, and WordPress Core.
- **Changelog Interface**: Integrated a dedicated tab in settings to view technical changes directly within the dashboard.

### Fixed
- **Login Security**: Implemented a robust fallback mechanism for the Custom Login URL to prevent 404 errors on Nginx/Permalinks environments.
