# Modifications from Goose

This file is the exact, machine-checked change inventory for AccordLock Desktop.
It implements the modified-file notice boundary for the Apache License 2.0
without placing invalid comments inside strict data formats or binary assets.

## Pinned upstream

- Project: [https://github.com/aaif-goose/goose](https://github.com/aaif-goose/goose)
- Version: `v1.47.0`
- Commit: `f9c7aaccde4834810dfd13d5efa8f0d39ba28a20`
- Tree: `a640469c0b798464250561cca0238c4cabfbf5c1`
- Manifest: `GOOSE_UPSTREAM_MANIFEST.txt`
- Intentionally omitted upstream subtrees: `documentation/` and `services/ask-ai-bot/`

## Audited result

- 2369 files in the pinned upstream tree
- 855 upstream files under the two explicit exclusions
- 366 inherited files modified and distributed
- 349 modified text/source files with an in-file notice
- 17 modified generated, strict-data, or binary files documented as exceptions
- 1106 inherited files distributed unchanged
- 222 AccordLock-only files
- 42 other upstream files omitted from this distribution

The standard in-file notice is:

> Modified by AccordLock contributors; see UPSTREAM.md.

Comments are placed after shebangs, XML declarations, Docker syntax
directives, and other required leading syntax. The runtime system-prompt
notice uses a Tera comment and is removed before model input. Package JSON
uses a schema-neutral top-level metadata field.

## Modified inherited files with in-file notices

- `.gitattributes`
- `.github/DISCUSSION_TEMPLATE/qa.yml`
- `.github/ISSUE_TEMPLATE/bug_report.md`
- `.github/ISSUE_TEMPLATE/feature_request.md`
- `.github/dependabot.yml`
- `.github/pull_request_template.md`
- `.github/workflows/build-cli-linux.yml`
- `.github/workflows/build-cli.yml`
- `.github/workflows/build-notify.yml`
- `.github/workflows/bundle-desktop-linux.yml`
- `.github/workflows/bundle-macos.yml`
- `.github/workflows/bundle-windows.yml`
- `.github/workflows/canary.yml`
- `.github/workflows/cargo-deny.yml`
- `.github/workflows/cargo-machete.yml`
- `.github/workflows/check-release-pr.yaml`
- `.github/workflows/ci.yml`
- `.github/workflows/close-release-pr-on-tag.yaml`
- `.github/workflows/code-review.yml`
- `.github/workflows/create-release-branch.yaml`
- `.github/workflows/create-version-bump-pr.yaml`
- `.github/workflows/dependabot-auto-merge.yml`
- `.github/workflows/deploy-docs-and-extensions.yml`
- `.github/workflows/docs-update-cli-ref.yml`
- `.github/workflows/goose-issue-solver.yml`
- `.github/workflows/goose-pr-reviewer.yml`
- `.github/workflows/goose-release-notes.yml`
- `.github/workflows/maven-sdk.yml`
- `.github/workflows/minor-release.yaml`
- `.github/workflows/patch-release.yaml`
- `.github/workflows/pr-smoke-test.yml`
- `.github/workflows/pr-website-preview.yml`
- `.github/workflows/publish-ask-ai-bot.yml`
- `.github/workflows/publish-docker.yml`
- `.github/workflows/publish-npm.yml`
- `.github/workflows/python-sdk-wheels.yml`
- `.github/workflows/quarantine.yml`
- `.github/workflows/recipe-security-scanner.yml`
- `.github/workflows/release-branches.yml`
- `.github/workflows/release.yml`
- `.github/workflows/scorecard.yml`
- `.github/workflows/stale.yml`
- `.github/workflows/take.yml`
- `.github/workflows/update-health-dashboard.yml`
- `.github/workflows/update-release-pr.yaml`
- `BUILDING_DOCKER.md`
- `BUILDING_LINUX.md`
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- `CUSTOM_DISTROS.md`
- `Cargo.toml`
- `Dockerfile`
- `GOVERNANCE.md`
- `Justfile`
- `README.md`
- `RELEASE.md`
- `RELEASE_CHECKLIST.md`
- `SECURITY.md`
- `crates/goose-cli/Cargo.toml`
- `crates/goose-cli/src/commands/configure.rs`
- `crates/goose-cli/src/commands/session.rs`
- `crates/goose-cli/src/commands/update.rs`
- `crates/goose-cli/src/session/builder.rs`
- `crates/goose-cli/src/session/output.rs`
- `crates/goose-mcp/src/computercontroller/mod.rs`
- `crates/goose-mcp/src/peekaboo/mod.rs`
- `crates/goose-mcp/src/subprocess.rs`
- `crates/goose-provider-types/src/conversation/message.rs`
- `crates/goose-providers/Cargo.toml`
- `crates/goose-providers/src/api_client.rs`
- `crates/goose-providers/src/declarative.rs`
- `crates/goose/Cargo.toml`
- `crates/goose/src/acp/server.rs`
- `crates/goose/src/acp/server/manage_sessions.rs`
- `crates/goose/src/acp/server/new_session.rs`
- `crates/goose/src/acp/server/tools.rs`
- `crates/goose/src/agents/agent.rs`
- `crates/goose/src/agents/execute_commands.rs`
- `crates/goose/src/agents/extension.rs`
- `crates/goose/src/agents/extension_manager.rs`
- `crates/goose/src/agents/mcp_client.rs`
- `crates/goose/src/agents/mod.rs`
- `crates/goose/src/agents/platform_extensions/developer/edit.rs`
- `crates/goose/src/agents/platform_extensions/developer/mod.rs`
- `crates/goose/src/agents/platform_extensions/developer/shell.rs`
- `crates/goose/src/agents/platform_extensions/developer/tree.rs`
- `crates/goose/src/agents/platform_extensions/mod.rs`
- `crates/goose/src/agents/platform_extensions/summarize.rs`
- `crates/goose/src/agents/prompt_manager.rs`
- `crates/goose/src/agents/reply_parts.rs`
- `crates/goose/src/agents/retry.rs`
- `crates/goose/src/agents/state_machine/ops_compaction.rs`
- `crates/goose/src/agents/state_machine/ops_doctor.rs`
- `crates/goose/src/agents/state_machine/ops_llm.rs`
- `crates/goose/src/agents/state_machine/ops_recipe.rs`
- `crates/goose/src/agents/state_machine/ops_retry.rs`
- `crates/goose/src/agents/state_machine/ops_toolcalling.rs`
- `crates/goose/src/agents/state_machine/tests/compaction_lifecycle.rs`
- `crates/goose/src/agents/state_machine/tests/pipeline.rs`
- `crates/goose/src/agents/tool_execution.rs`
- `crates/goose/src/agents/types.rs`
- `crates/goose/src/config/base.rs`
- `crates/goose/src/dictation/providers.rs`
- `crates/goose/src/dictation/whisper.rs`
- `crates/goose/src/hooks/mod.rs`
- `crates/goose/src/oauth/oauth_callback.html`
- `crates/goose/src/plugins/mod.rs`
- `crates/goose/src/posthog.rs`
- `crates/goose/src/prompts/system.md`
- `crates/goose/src/providers/catalog_util.rs`
- `crates/goose/src/providers/chatgpt_codex.rs`
- `crates/goose/src/providers/cursor_agent.rs`
- `crates/goose/src/providers/gcpauth.rs`
- `crates/goose/src/providers/gemini_oauth.rs`
- `crates/goose/src/providers/githubcopilot.rs`
- `crates/goose/src/providers/huggingface_auth.rs`
- `crates/goose/src/providers/inventory/mod.rs`
- `crates/goose/src/providers/inventory/registrations.rs`
- `crates/goose/src/providers/kimicode.rs`
- `crates/goose/src/providers/mod.rs`
- `crates/goose/src/providers/oauth.rs`
- `crates/goose/src/providers/provider_registry.rs`
- `crates/goose/src/providers/provider_secrets.rs`
- `crates/goose/src/providers/toolshim.rs`
- `crates/goose/src/providers/xai_oauth.rs`
- `crates/goose/src/subprocess.rs`
- `crates/goose/tests/acp_common_tests/mod.rs`
- `crates/goose/tests/acp_provider_test.rs`
- `crates/goose/tests/acp_server_test.rs`
- `download_cli.ps1`
- `download_cli.sh`
- `recipe-scanner/Dockerfile`
- `recipe-scanner/scan-recipe.sh`
- `scripts/build-windows.ps1`
- `scripts/pre-release.sh`
- `ui/desktop/.gitignore`
- `ui/desktop/README.md`
- `ui/desktop/entitlements.plist`
- `ui/desktop/eslint.config.js`
- `ui/desktop/forge.config.ts`
- `ui/desktop/forge.deb.desktop`
- `ui/desktop/forge.rpm.desktop`
- `ui/desktop/index.html`
- `ui/desktop/package.json`
- `ui/desktop/scripts/README.md`
- `ui/desktop/scripts/i18n-check.js`
- `ui/desktop/scripts/i18n-compile.js`
- `ui/desktop/scripts/prepare-platform-binaries.js`
- `ui/desktop/scripts/prepare-windows-npm.bat`
- `ui/desktop/scripts/prepare-windows-npm.sh`
- `ui/desktop/src/App.test.tsx`
- `ui/desktop/src/App.tsx`
- `ui/desktop/src/__tests__/createSession.test.ts`
- `ui/desktop/src/__tests__/projectSessions.test.ts`
- `ui/desktop/src/acp/__tests__/chatSessionController.test.ts`
- `ui/desktop/src/acp/__tests__/errors.test.ts`
- `ui/desktop/src/acp/__tests__/sessions.test.ts`
- `ui/desktop/src/acp/autocomplete.ts`
- `ui/desktop/src/acp/chatNotifications.ts`
- `ui/desktop/src/acp/errors.ts`
- `ui/desktop/src/acp/permissions.ts`
- `ui/desktop/src/acp/prompts.ts`
- `ui/desktop/src/acp/sessions.ts`
- `ui/desktop/src/app-update.yml`
- `ui/desktop/src/components/BaseChat.tsx`
- `ui/desktop/src/components/ChatInput.tsx`
- `ui/desktop/src/components/ConfigContext.tsx`
- `ui/desktop/src/components/ElicitationRequest.tsx`
- `ui/desktop/src/components/ErrorBoundary.tsx`
- `ui/desktop/src/components/ExtensionInstallModal.test.tsx`
- `ui/desktop/src/components/ExtensionInstallModal.tsx`
- `ui/desktop/src/components/GitBranchIndicator.tsx`
- `ui/desktop/src/components/GooseMessage.tsx`
- `ui/desktop/src/components/GooseSidebar/ThemeSelector.tsx`
- `ui/desktop/src/components/GroupedExtensionLoadingToast.tsx`
- `ui/desktop/src/components/Hub.tsx`
- `ui/desktop/src/components/ImagePreview.tsx`
- `ui/desktop/src/components/LauncherView.tsx`
- `ui/desktop/src/components/Layout/AppLayout.tsx`
- `ui/desktop/src/components/Layout/NavigationPanel.tsx`
- `ui/desktop/src/components/LoadingGoose.tsx`
- `ui/desktop/src/components/MarkdownContent.tsx`
- `ui/desktop/src/components/McpApps/McpAppRenderer.tsx`
- `ui/desktop/src/components/ModelAndProviderContext.tsx`
- `ui/desktop/src/components/ParameterInputModal.tsx`
- `ui/desktop/src/components/RecipeHeader.tsx`
- `ui/desktop/src/components/SessionActionsHeader.tsx`
- `ui/desktop/src/components/SessionIndicators.tsx`
- `ui/desktop/src/components/TelemetryConsentPrompt.tsx`
- `ui/desktop/src/components/ToolApprovalButtons.test.tsx`
- `ui/desktop/src/components/ToolApprovalButtons.tsx`
- `ui/desktop/src/components/ToolCallArguments.tsx`
- `ui/desktop/src/components/ToolCallConfirmation.tsx`
- `ui/desktop/src/components/UserMessage.tsx`
- `ui/desktop/src/components/__tests__/GroupedExtensionLoadingToast.test.tsx`
- `ui/desktop/src/components/__tests__/ParameterInputModal.test.tsx`
- `ui/desktop/src/components/alerts/AlertBox.tsx`
- `ui/desktop/src/components/apps/AppsView.tsx`
- `ui/desktop/src/components/apps/StandaloneAppView.tsx`
- `ui/desktop/src/components/bottom_menu/BottomMenuExtensionSelection.tsx`
- `ui/desktop/src/components/bottom_menu/CostTracker.tsx`
- `ui/desktop/src/components/bottom_menu/DirSwitcher.tsx`
- `ui/desktop/src/components/common/InlineEditText.tsx`
- `ui/desktop/src/components/context_management/CreditsExhaustedNotification.tsx`
- `ui/desktop/src/components/extensions/ExtensionsView.tsx`
- `ui/desktop/src/components/icons/TrashIcon.tsx`
- `ui/desktop/src/components/onboarding/LocalModelPicker.tsx`
- `ui/desktop/src/components/onboarding/OnboardingGuard.tsx`
- `ui/desktop/src/components/onboarding/OnboardingSuccess.tsx`
- `ui/desktop/src/components/onboarding/PrivacyInfoModal.tsx`
- `ui/desktop/src/components/onboarding/ProviderConfigForm.tsx`
- `ui/desktop/src/components/onboarding/ProviderSelector.tsx`
- `ui/desktop/src/components/parameter/ParameterInput.tsx`
- `ui/desktop/src/components/recipes/CreateEditRecipeModal.tsx`
- `ui/desktop/src/components/recipes/ImportRecipeForm.tsx`
- `ui/desktop/src/components/recipes/RecipeActivities.tsx`
- `ui/desktop/src/components/recipes/RecipeActivityEditor.tsx`
- `ui/desktop/src/components/recipes/RecipesView.tsx`
- `ui/desktop/src/components/recipes/shared/CreateSubRecipeInline.tsx`
- `ui/desktop/src/components/recipes/shared/InstructionsEditor.tsx`
- `ui/desktop/src/components/recipes/shared/JsonSchemaEditor.tsx`
- `ui/desktop/src/components/recipes/shared/RecipeExtensionSelector.tsx`
- `ui/desktop/src/components/recipes/shared/RecipeFormFields.tsx`
- `ui/desktop/src/components/recipes/shared/RecipeModelSelector.tsx`
- `ui/desktop/src/components/recipes/shared/SubRecipeEditor.tsx`
- `ui/desktop/src/components/recipes/shared/SubRecipeModal.tsx`
- `ui/desktop/src/components/recipes/shared/__tests__/RecipeActivityEditor.test.tsx`
- `ui/desktop/src/components/recipes/shared/__tests__/RecipeFormFields.test.tsx`
- `ui/desktop/src/components/schedule/ScheduleDetailView.tsx`
- `ui/desktop/src/components/schedule/ScheduleModal.tsx`
- `ui/desktop/src/components/schedule/SchedulesView.tsx`
- `ui/desktop/src/components/schedule/__tests__/ScheduleModal.test.tsx`
- `ui/desktop/src/components/sessions/SessionListView.tsx`
- `ui/desktop/src/components/sessions/SessionsView.tsx`
- `ui/desktop/src/components/settings/PromptsSettingsSection.tsx`
- `ui/desktop/src/components/settings/SettingsView.tsx`
- `ui/desktop/src/components/settings/app/AppSettingsSection.tsx`
- `ui/desktop/src/components/settings/app/ExternalBackendSection.tsx`
- `ui/desktop/src/components/settings/app/TelemetrySettings.tsx`
- `ui/desktop/src/components/settings/app/UpdateSection.tsx`
- `ui/desktop/src/components/settings/auth/AuthSettingsSection.test.tsx`
- `ui/desktop/src/components/settings/auth/AuthSettingsSection.tsx`
- `ui/desktop/src/components/settings/auth/HuggingFaceSignInPrompt.tsx`
- `ui/desktop/src/components/settings/chat/ChatSettingsSection.tsx`
- `ui/desktop/src/components/settings/chat/GoosehintsModal.tsx`
- `ui/desktop/src/components/settings/chat/GoosehintsSection.tsx`
- `ui/desktop/src/components/settings/chat/SpellcheckToggle.tsx`
- `ui/desktop/src/components/settings/config/ConfigSettings.tsx`
- `ui/desktop/src/components/settings/dictation/DictationSettings.tsx`
- `ui/desktop/src/components/settings/dictation/LocalModelManager.tsx`
- `ui/desktop/src/components/settings/dictation/MicrophoneSelector.tsx`
- `ui/desktop/src/components/settings/extensions/ExtensionsSection.tsx`
- `ui/desktop/src/components/settings/extensions/deeplink.test.ts`
- `ui/desktop/src/components/settings/extensions/deeplink.ts`
- `ui/desktop/src/components/settings/extensions/modal/EnvVarsSection.tsx`
- `ui/desktop/src/components/settings/extensions/modal/ExtensionConfigFields.tsx`
- `ui/desktop/src/components/settings/extensions/modal/ExtensionInfoFields.tsx`
- `ui/desktop/src/components/settings/extensions/modal/ExtensionModal.tsx`
- `ui/desktop/src/components/settings/extensions/modal/ExtensionTimeoutField.tsx`
- `ui/desktop/src/components/settings/extensions/modal/HeadersSection.tsx`
- `ui/desktop/src/components/settings/extensions/utils.test.ts`
- `ui/desktop/src/components/settings/keyboard/KeyboardShortcutsSection.tsx`
- `ui/desktop/src/components/settings/keyboard/ShortcutRecorder.tsx`
- `ui/desktop/src/components/settings/localInference/HuggingFaceModelSearch.tsx`
- `ui/desktop/src/components/settings/localInference/LocalInferenceSettings.tsx`
- `ui/desktop/src/components/settings/localInference/ModelSettingsPanel.tsx`
- `ui/desktop/src/components/settings/mode/ConfigureApproveMode.tsx`
- `ui/desktop/src/components/settings/mode/ConversationLimitsDropdown.tsx`
- `ui/desktop/src/components/settings/mode/ModeSelectionItem.tsx`
- `ui/desktop/src/components/settings/models/ModelsSection.tsx`
- `ui/desktop/src/components/settings/models/bottom_bar/ModelsBottomBar.test.tsx`
- `ui/desktop/src/components/settings/models/bottom_bar/ModelsBottomBar.tsx`
- `ui/desktop/src/components/settings/models/predefinedModelsUtils.ts`
- `ui/desktop/src/components/settings/models/subcomponents/SwitchModelModal.tsx`
- `ui/desktop/src/components/settings/permission/PermissionModal.tsx`
- `ui/desktop/src/components/settings/permission/PermissionRulesModal.tsx`
- `ui/desktop/src/components/settings/permission/PermissionSetting.tsx`
- `ui/desktop/src/components/settings/providers/AcpReadinessPanel.tsx`
- `ui/desktop/src/components/settings/providers/ProviderSettingsPage.tsx`
- `ui/desktop/src/components/settings/providers/modal/ProviderConfigurationModal.tsx`
- `ui/desktop/src/components/settings/providers/modal/constants.tsx`
- `ui/desktop/src/components/settings/providers/modal/subcomponents/ProviderCatalogPicker.tsx`
- `ui/desktop/src/components/settings/providers/modal/subcomponents/ProviderSetupActions.tsx`
- `ui/desktop/src/components/settings/providers/modal/subcomponents/SecureStorageNotice.tsx`
- `ui/desktop/src/components/settings/providers/modal/subcomponents/forms/CustomProviderForm.tsx`
- `ui/desktop/src/components/settings/providers/subcomponents/buttons/DefaultCardButtons.tsx`
- `ui/desktop/src/components/settings/reset_provider/ResetProviderSection.tsx`
- `ui/desktop/src/components/settings/response_styles/ResponseStyleSelectionItem.tsx`
- `ui/desktop/src/components/settings/security/SecurityToggle.tsx`
- `ui/desktop/src/components/skills/SkillsView.tsx`
- `ui/desktop/src/components/ui/ConfirmationModal.tsx`
- `ui/desktop/src/components/ui/Diagnostics.tsx`
- `ui/desktop/src/components/ui/RecipeWarningModal.tsx`
- `ui/desktop/src/constants/events.ts`
- `ui/desktop/src/contexts/ThemeContext.tsx`
- `ui/desktop/src/desktopFileAccess.test.ts`
- `ui/desktop/src/desktopFileAccess.ts`
- `ui/desktop/src/gooseServe.test.ts`
- `ui/desktop/src/gooseServe.ts`
- `ui/desktop/src/gooseServeLeaseRegistry.test.ts`
- `ui/desktop/src/gooseServeLeaseRegistry.ts`
- `ui/desktop/src/hooks/useAudioRecorder.ts`
- `ui/desktop/src/hooks/useAutoSubmit.test.tsx`
- `ui/desktop/src/hooks/useChatSession.ts`
- `ui/desktop/src/hooks/useChatSessionTypes.ts`
- `ui/desktop/src/hooks/useFileDrop.ts`
- `ui/desktop/src/hooks/useNavigationItems.ts`
- `ui/desktop/src/hooks/useNavigationSessions.ts`
- `ui/desktop/src/i18n/i18n.test.ts`
- `ui/desktop/src/i18n/index.ts`
- `ui/desktop/src/i18n/test-utils.tsx`
- `ui/desktop/src/images/icon.svg`
- `ui/desktop/src/main.ts`
- `ui/desktop/src/platform/windows/bin/README.md`
- `ui/desktop/src/platform/windows/bin/jbang.cmd`
- `ui/desktop/src/platform/windows/bin/npx.cmd`
- `ui/desktop/src/preload.fileAccess.test.ts`
- `ui/desktop/src/preload.ts`
- `ui/desktop/src/recipe/index.ts`
- `ui/desktop/src/recipe/recipe_management.ts`
- `ui/desktop/src/renderer.tsx`
- `ui/desktop/src/sessions.ts`
- `ui/desktop/src/styles/main.css`
- `ui/desktop/src/suspense-loader.tsx`
- `ui/desktop/src/test/setup.ts`
- `ui/desktop/src/theme/theme-tokens.ts`
- `ui/desktop/src/toasts.tsx`
- `ui/desktop/src/updates.ts`
- `ui/desktop/src/utils/__tests__/csp.test.ts`
- `ui/desktop/src/utils/analytics.ts`
- `ui/desktop/src/utils/autoUpdater.ts`
- `ui/desktop/src/utils/conversionUtils.test.ts`
- `ui/desktop/src/utils/conversionUtils.ts`
- `ui/desktop/src/utils/csp.ts`
- `ui/desktop/src/utils/date.ts`
- `ui/desktop/src/utils/extensionErrorUtils.ts`
- `ui/desktop/src/utils/gitBranchIpc.ts`
- `ui/desktop/src/utils/githubUpdater.ts`
- `ui/desktop/src/utils/navigationUtils.ts`
- `ui/desktop/src/utils/projectSessions.ts`
- `ui/desktop/src/utils/settings.ts`
- `ui/desktop/src/utils/urlSecurity.ts`
- `ui/desktop/src/utils/winShims.ts`
- `ui/desktop/vite.main.config.mts`
- `ui/desktop/vite.preload.config.mts`
- `ui/desktop/vitest.config.ts`
- `ui/package.json`
- `ui/pnpm-workspace.yaml`
- `ui/sdk/package.json`

## Modified inherited files documented out of band

These files are still modified-file exceptions, not untracked changes. Adding
a comment would corrupt a strict format, alter a binary payload, or be erased
by the owning generator. Their upstream and current Git object identities are
recorded by the manifest and the repository history.

| File | Why an in-file notice is unsafe |
| --- | --- |
| `Cargo.lock` | Cargo-generated lockfile; manual comments are not stable under regeneration. |
| `crates/goose/src/agents/snapshots/goose__agents__prompt_manager__tests__all_platform_extensions.snap` | Insta-generated prompt snapshot; an in-file comment would change the asserted prompt or invalidate the snapshot metadata header. |
| `ui/desktop/src/built-in-extensions.json` | Strict JSON array consumed as extension data; no schema-neutral comment or metadata location exists. |
| `ui/desktop/src/components/settings/extensions/bundled-extensions.json` | Strict JSON array consumed as extension data; no schema-neutral comment or metadata location exists. |
| `ui/desktop/src/i18n/messages/en.json` | Strict message-catalog JSON; an extra key changes the compiled catalog rather than recording inert metadata. |
| `ui/desktop/src/images/icon-512.png` | Binary PNG application asset. |
| `ui/desktop/src/images/icon-light.icns` | Binary Apple icon asset. |
| `ui/desktop/src/images/icon-light.png` | Binary PNG application asset. |
| `ui/desktop/src/images/icon.icns` | Binary Apple icon asset. |
| `ui/desktop/src/images/icon.ico` | Binary Windows icon asset. |
| `ui/desktop/src/images/icon.png` | Binary PNG application asset. |
| `ui/desktop/src/images/icon@2x.png` | Binary PNG application asset. |
| `ui/desktop/src/images/iconTemplate.png` | Binary PNG tray asset. |
| `ui/desktop/src/images/iconTemplate@2x.png` | Binary PNG tray asset. |
| `ui/desktop/src/images/iconTemplateUpdate.png` | Binary PNG tray asset. |
| `ui/desktop/src/images/iconTemplateUpdate@2x.png` | Binary PNG tray asset. |
| `ui/pnpm-lock.yaml` | pnpm-generated lockfile; manual comments are not stable under regeneration. |

## Compliance note

Apache-2.0 section 4(b) requires modified files to carry prominent change
notices. Source files do so directly. For the listed strict-data, generated,
and binary exceptions, AccordLock uses this adjacent exact inventory plus Git
object provenance because an in-file comment is technically unsafe. This is a
documented engineering compromise, not legal advice; release counsel should
confirm that the out-of-band handling is sufficient for the intended distribution.

## AccordLock-only files

- `.github/workflows/accordlock-publication-guard.yml`
- `.github/workflows/accordlock-technical-preview-ci.yml`
- `ACCORDLOCK_DISTRIBUTION_RUST_PROFILE.json`
- `BRAND.md`
- `GOOSE_UPSTREAM_MANIFEST.txt`
- `MODIFICATIONS.md`
- `NOTICE`
- `THIRD_PARTY_NOTICES.md`
- `UPSTREAM.md`
- `crates/goose-providers/src/declarative/definitions/opencode.json`
- `crates/goose/src/agents/accordlock_authorization.rs`
- `crates/goose/src/agents/accordlock_filesystem.rs`
- `crates/goose/src/agents/accordlock_network.rs`
- `crates/goose/src/agents/accordlock_terminal.rs`
- `crates/goose/src/dictation/whisper_data/README.md`
- `crates/goose/src/prompts/accordlock_distribution.md`
- `crates/goose/src/providers/credential_vault.rs`
- `scripts/build-macos.ps1`
- `scripts/check_accordlock_publication.py`
- `scripts/check_upstream_modifications.py`
- `scripts/generate-release-sboms.ps1`
- `scripts/syft-release.yaml`
- `scripts/tests/test_check_accordlock_publication.py`
- `scripts/tests/test_upstream_modifications.py`
- `ui/desktop/ACCORDLOCK_DISTRIBUTION.md`
- `ui/desktop/entitlements-inherit.plist`
- `ui/desktop/scripts/accordlock-windows-signing.js`
- `ui/desktop/scripts/generate-accordlock-icons.mjs`
- `ui/desktop/scripts/prepare-platform-binaries.test.js`
- `ui/desktop/scripts/sanitize-windows-build-paths.js`
- `ui/desktop/scripts/sanitize-windows-build-paths.test.js`
- `ui/desktop/scripts/sign-accordlock-windows-sidecars.js`
- `ui/desktop/scripts/verify-accordlock-backend.js`
- `ui/desktop/scripts/verify-accordlock-macos-sidecars.js`
- `ui/desktop/src/accordlock/approvalInbox.test.ts`
- `ui/desktop/src/accordlock/approvalInbox.ts`
- `ui/desktop/src/accordlock/approvalInboxBridge.ts`
- `ui/desktop/src/accordlock/approvalInboxIpc.ts`
- `ui/desktop/src/accordlock/approvalInboxStore.ts`
- `ui/desktop/src/accordlock/approvalNotificationRegistry.test.ts`
- `ui/desktop/src/accordlock/approvalNotificationRegistry.ts`
- `ui/desktop/src/accordlock/approvalNotifications.test.ts`
- `ui/desktop/src/accordlock/approvalNotifications.ts`
- `ui/desktop/src/accordlock/auditTimeline.test.ts`
- `ui/desktop/src/accordlock/auditTimeline.ts`
- `ui/desktop/src/accordlock/decisionSingleFlight.test.ts`
- `ui/desktop/src/accordlock/decisionSingleFlight.ts`
- `ui/desktop/src/accordlock/deploymentPreflight.test.ts`
- `ui/desktop/src/accordlock/deploymentPreflight.ts`
- `ui/desktop/src/accordlock/deploymentPreflightCiEnrollmentController.test.ts`
- `ui/desktop/src/accordlock/deploymentPreflightCiEnrollmentController.ts`
- `ui/desktop/src/accordlock/deploymentPreflightCiEvidence.crossContract.test.ts`
- `ui/desktop/src/accordlock/deploymentPreflightCiEvidence.test.ts`
- `ui/desktop/src/accordlock/deploymentPreflightCiEvidence.ts`
- `ui/desktop/src/accordlock/deploymentPreflightReceipt.test.ts`
- `ui/desktop/src/accordlock/deploymentPreflightReceipt.ts`
- `ui/desktop/src/accordlock/deploymentPreflightReceiptArchive.test.ts`
- `ui/desktop/src/accordlock/deploymentPreflightReceiptArchive.ts`
- `ui/desktop/src/accordlock/environmentProfileIpc.test.ts`
- `ui/desktop/src/accordlock/environmentProfileIpc.ts`
- `ui/desktop/src/accordlock/environmentProfilePreflightController.test.ts`
- `ui/desktop/src/accordlock/environmentProfilePreflightController.ts`
- `ui/desktop/src/accordlock/environmentProfiles.ts`
- `ui/desktop/src/accordlock/globalAudit.test.ts`
- `ui/desktop/src/accordlock/globalAudit.ts`
- `ui/desktop/src/accordlock/intentControl.test.ts`
- `ui/desktop/src/accordlock/intentControl.ts`
- `ui/desktop/src/accordlock/intentReview.test.ts`
- `ui/desktop/src/accordlock/intentReview.ts`
- `ui/desktop/src/accordlock/notificationNavigation.test.ts`
- `ui/desktop/src/accordlock/notificationNavigation.ts`
- `ui/desktop/src/accordlock/pinnedCiRoute.test.ts`
- `ui/desktop/src/accordlock/pinnedCiRoute.ts`
- `ui/desktop/src/accordlock/runtimeAudit.test.ts`
- `ui/desktop/src/accordlock/runtimeAudit.ts`
- `ui/desktop/src/accordlock/taskAuthorizationContract.ts`
- `ui/desktop/src/accordlock/taskAuthorizationStore.test.ts`
- `ui/desktop/src/accordlock/taskAuthorizationStore.ts`
- `ui/desktop/src/accordlock/taskBridge.test.ts`
- `ui/desktop/src/accordlock/taskBridge.ts`
- `ui/desktop/src/accordlock/taskExtensions.test.ts`
- `ui/desktop/src/accordlock/taskExtensions.ts`
- `ui/desktop/src/accordlock/taskIntent.test.ts`
- `ui/desktop/src/accordlock/taskIntent.ts`
- `ui/desktop/src/accordlock/taskIpc.ts`
- `ui/desktop/src/accordlock/taskLifecycle.test.ts`
- `ui/desktop/src/accordlock/taskLifecycle.ts`
- `ui/desktop/src/accordlock/taskNotifications.test.ts`
- `ui/desktop/src/accordlock/taskNotifications.ts`
- `ui/desktop/src/accordlock/taskObjective.test.ts`
- `ui/desktop/src/accordlock/taskObjective.ts`
- `ui/desktop/src/accordlock/taskReport.test.ts`
- `ui/desktop/src/accordlock/taskReport.ts`
- `ui/desktop/src/accordlock/taskStatusCopy.test.ts`
- `ui/desktop/src/accordlock/taskStatusCopy.ts`
- `ui/desktop/src/accordlock/useTaskSubmit.test.ts`
- `ui/desktop/src/accordlock/useTaskSubmit.ts`
- `ui/desktop/src/accordlockActionApproval.test.ts`
- `ui/desktop/src/accordlockActionApproval.ts`
- `ui/desktop/src/accordlockActionApprovalWindow.test.ts`
- `ui/desktop/src/accordlockActionApprovalWindow.ts`
- `ui/desktop/src/accordlockApprovalCenterGate.test.ts`
- `ui/desktop/src/accordlockApprovalCenterGate.ts`
- `ui/desktop/src/accordlockApprovalChannels.test.ts`
- `ui/desktop/src/accordlockApprovalChannels.ts`
- `ui/desktop/src/accordlockApprovalNotificationDispatcher.test.ts`
- `ui/desktop/src/accordlockApprovalNotificationDispatcher.ts`
- `ui/desktop/src/accordlockApprovalProxy.test.ts`
- `ui/desktop/src/accordlockApprovalProxy.ts`
- `ui/desktop/src/accordlockBackendBinding.test.ts`
- `ui/desktop/src/accordlockBackendBinding.ts`
- `ui/desktop/src/accordlockBootstrap.test.ts`
- `ui/desktop/src/accordlockBootstrap.ts`
- `ui/desktop/src/accordlockDesktopBranding.test.ts`
- `ui/desktop/src/accordlockDesktopBranding.ts`
- `ui/desktop/src/accordlockDesktopSecurity.test.ts`
- `ui/desktop/src/accordlockDesktopSecurity.ts`
- `ui/desktop/src/accordlockEmbeddedIntegrity.test.ts`
- `ui/desktop/src/accordlockEmbeddedIntegrity.ts`
- `ui/desktop/src/accordlockEnvironmentProfileStore.test.ts`
- `ui/desktop/src/accordlockEnvironmentProfileStore.ts`
- `ui/desktop/src/accordlockHistoricalLedger.test.ts`
- `ui/desktop/src/accordlockHistoricalLedger.ts`
- `ui/desktop/src/accordlockMacOSSigning.test.js`
- `ui/desktop/src/accordlockNetworkPolicy.test.ts`
- `ui/desktop/src/accordlockNetworkPolicy.ts`
- `ui/desktop/src/accordlockPreflightRunnerAdapter.test.ts`
- `ui/desktop/src/accordlockPreflightRunnerAdapter.ts`
- `ui/desktop/src/accordlockPreflightTrustStore.test.ts`
- `ui/desktop/src/accordlockPreflightTrustStore.ts`
- `ui/desktop/src/accordlockRemoteApprovals.test.ts`
- `ui/desktop/src/accordlockRemoteApprovals.ts`
- `ui/desktop/src/accordlockRestoreWindow.test.ts`
- `ui/desktop/src/accordlockRestoreWindow.ts`
- `ui/desktop/src/accordlockRuntime.test.ts`
- `ui/desktop/src/accordlockRuntime.ts`
- `ui/desktop/src/accordlockSettingsConfirmationWindow.test.ts`
- `ui/desktop/src/accordlockSettingsConfirmationWindow.ts`
- `ui/desktop/src/accordlockTaskApprovalWindow.test.ts`
- `ui/desktop/src/accordlockTaskApprovalWindow.ts`
- `ui/desktop/src/accordlockTaskAuditIndex.test.ts`
- `ui/desktop/src/accordlockTaskAuditIndex.ts`
- `ui/desktop/src/accordlockTaskControl.test.ts`
- `ui/desktop/src/accordlockTaskControl.ts`
- `ui/desktop/src/accordlockTerminalPrograms.test.ts`
- `ui/desktop/src/accordlockTerminalPrograms.ts`
- `ui/desktop/src/accordlockWindowsSigning.test.js`
- `ui/desktop/src/accordlockWorkspace.test.ts`
- `ui/desktop/src/accordlockWorkspace.ts`
- `ui/desktop/src/acp/__tests__/projects.test.ts`
- `ui/desktop/src/acp/projects.ts`
- `ui/desktop/src/components/ErrorBoundary.test.tsx`
- `ui/desktop/src/components/Hub.deploymentPreflight.test.tsx`
- `ui/desktop/src/components/Hub.test.ts`
- `ui/desktop/src/components/Layout/NavigationPanel.test.tsx`
- `ui/desktop/src/components/SessionIndicators.test.tsx`
- `ui/desktop/src/components/accordlock/AccordLockBrand.test.tsx`
- `ui/desktop/src/components/accordlock/AccordLockBrand.tsx`
- `ui/desktop/src/components/accordlock/ApprovalCenter.test.tsx`
- `ui/desktop/src/components/accordlock/ApprovalCenter.tsx`
- `ui/desktop/src/components/accordlock/ApprovalCenterRoute.test.tsx`
- `ui/desktop/src/components/accordlock/ApprovalCenterRoute.tsx`
- `ui/desktop/src/components/accordlock/ApprovalInboxController.test.tsx`
- `ui/desktop/src/components/accordlock/ApprovalInboxController.tsx`
- `ui/desktop/src/components/accordlock/DeploymentPreflightDialog.test.tsx`
- `ui/desktop/src/components/accordlock/DeploymentPreflightDialog.tsx`
- `ui/desktop/src/components/accordlock/DeploymentPreflightHistoryDialog.tsx`
- `ui/desktop/src/components/accordlock/DeploymentPreflightResult.test.tsx`
- `ui/desktop/src/components/accordlock/DeploymentPreflightResult.tsx`
- `ui/desktop/src/components/accordlock/GlobalAuditView.test.tsx`
- `ui/desktop/src/components/accordlock/GlobalAuditView.tsx`
- `ui/desktop/src/components/accordlock/IntentControlBadge.tsx`
- `ui/desktop/src/components/accordlock/TaskAuditTimeline.test.tsx`
- `ui/desktop/src/components/accordlock/TaskAuditTimeline.tsx`
- `ui/desktop/src/components/accordlock/TaskAuthorizationController.tsx`
- `ui/desktop/src/components/accordlock/TaskAuthorizationDialog.test.tsx`
- `ui/desktop/src/components/accordlock/TaskAuthorizationDialog.tsx`
- `ui/desktop/src/components/accordlock/TaskStatusPanel.test.tsx`
- `ui/desktop/src/components/accordlock/TaskStatusPanel.tsx`
- `ui/desktop/src/components/bottom_menu/DirSwitcher.test.tsx`
- `ui/desktop/src/components/context_management/CreditsExhaustedNotification.test.ts`
- `ui/desktop/src/components/onboarding/OnboardingGuard.test.tsx`
- `ui/desktop/src/components/onboarding/ProductTourDialog.tsx`
- `ui/desktop/src/components/onboarding/ProviderConfigForm.test.tsx`
- `ui/desktop/src/components/onboarding/ProviderSelector.test.tsx`
- `ui/desktop/src/components/projects/ProjectPicker.test.tsx`
- `ui/desktop/src/components/projects/ProjectPicker.tsx`
- `ui/desktop/src/components/projects/ProjectsView.test.tsx`
- `ui/desktop/src/components/projects/ProjectsView.tsx`
- `ui/desktop/src/components/sessions/SessionListView.test.tsx`
- `ui/desktop/src/components/settings/SettingsView.test.tsx`
- `ui/desktop/src/components/settings/app/ApprovalChannelsSettings.test.tsx`
- `ui/desktop/src/components/settings/app/ApprovalChannelsSettings.tsx`
- `ui/desktop/src/components/settings/app/NetworkAccessSettings.test.tsx`
- `ui/desktop/src/components/settings/app/NetworkAccessSettings.tsx`
- `ui/desktop/src/components/settings/app/TerminalProgramsSettings.test.tsx`
- `ui/desktop/src/components/settings/app/TerminalProgramsSettings.tsx`
- `ui/desktop/src/components/settings/chat/ChatSettingsSection.test.tsx`
- `ui/desktop/src/components/settings/connections/EnvironmentConnectionsSettings.test.tsx`
- `ui/desktop/src/components/settings/connections/EnvironmentConnectionsSettings.tsx`
- `ui/desktop/src/components/settings/models/predefinedModelsUtils.test.ts`
- `ui/desktop/src/components/settings/providers/modal/subcomponents/ProviderCatalogPicker.test.tsx`
- `ui/desktop/src/hooks/useNavigationItems.test.ts`
- `ui/desktop/src/images/iconTray.png`
- `ui/desktop/src/images/iconTray@2x.png`
- `ui/desktop/src/images/iconTrayUpdate.png`
- `ui/desktop/src/images/iconTrayUpdate@2x.png`
- `ui/desktop/src/platform/darwin/bin/jbang`
- `ui/desktop/src/platform/darwin/bin/node`
- `ui/desktop/src/platform/darwin/bin/npx`
- `ui/desktop/src/platform/darwin/bin/system-tool-wrapper.sh`
- `ui/desktop/src/platform/darwin/bin/uvx`
- `ui/desktop/src/preload.bundle.test.ts`
- `ui/desktop/src/themeBootstrap.ts`
- `ui/desktop/src/utils/deepLinks.test.ts`
- `ui/desktop/src/utils/deepLinks.ts`
- `ui/desktop/src/utils/gitBranchAccess.test.ts`
- `ui/desktop/src/utils/gitBranchAccess.ts`
- `ui/desktop/src/utils/projectMatching.test.ts`
- `ui/desktop/src/utils/projectMatching.ts`
- `ui/desktop/src/utils/userFacingErrorBoundaries.test.ts`
- `ui/desktop/tests/integration/accordlock_control_channel.test.ts`

## Other omitted upstream files

The two excluded subtrees are represented in the pinned manifest and are not
repeated here. The following additional upstream files are not distributed:

- `.github/CODEOWNERS`
- `MAINTAINERS.md`
- `MERGE_FIXES.md`
- `crates/goose/src/agents/platform_extensions/code_execution.rs`
- `crates/goose/tests/acp_test_data/openai_builtin_execute.txt`
- `crates/goose/tests/acp_test_data/openai_builtin_final.txt`
- `crates/goose/tests/acp_test_data/openai_builtin_search.txt`
- `ui/desktop/.env`
- `ui/desktop/scripts/i18n-validate-locale.js`
- `ui/desktop/scripts/unregister-deeplink-protocols.js`
- `ui/desktop/src/bin/.gitkeep`
- `ui/desktop/src/bin/jbang`
- `ui/desktop/src/bin/node`
- `ui/desktop/src/bin/node-setup-common.sh`
- `ui/desktop/src/bin/npx`
- `ui/desktop/src/bin/uvx`
- `ui/desktop/src/i18n/messages/de.json`
- `ui/desktop/src/i18n/messages/es.json`
- `ui/desktop/src/i18n/messages/fr.json`
- `ui/desktop/src/i18n/messages/hi.json`
- `ui/desktop/src/i18n/messages/id.json`
- `ui/desktop/src/i18n/messages/it.json`
- `ui/desktop/src/i18n/messages/ja.json`
- `ui/desktop/src/i18n/messages/ko.json`
- `ui/desktop/src/i18n/messages/ms.json`
- `ui/desktop/src/i18n/messages/pt.json`
- `ui/desktop/src/i18n/messages/ru.json`
- `ui/desktop/src/i18n/messages/tr.json`
- `ui/desktop/src/i18n/messages/vi.json`
- `ui/desktop/src/i18n/messages/zh-CN.json`
- `ui/desktop/src/i18n/messages/zh-TW.json`
- `ui/desktop/src/images/Union@2x.svg`
- `ui/desktop/src/images/glyph.svg`
- `ui/desktop/src/images/loading-goose/1.svg`
- `ui/desktop/src/images/loading-goose/2.svg`
- `ui/desktop/src/images/loading-goose/3.svg`
- `ui/desktop/src/images/loading-goose/4.svg`
- `ui/desktop/src/images/loading-goose/5.svg`
- `ui/desktop/src/images/loading-goose/6.svg`
- `ui/desktop/src/images/loading-goose/7.svg`
- `ui/desktop/src/images/prepare.sh`
- `ui/desktop/tests/integration/test_providers_code_exec.test.ts`

## Reproduce the audit

From `desktop/`:

```console
python scripts/check_upstream_modifications.py
python -m unittest scripts.tests.test_upstream_modifications -v
```

The check is network-free. It fails if the pinned manifest, exact path sets,
file counts, exception list, in-file notices, or this report drift.
