// Modified by AccordLock contributors; see UPSTREAM.md.
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import type { Stats } from 'node:fs';
import path from 'node:path';
import { isAccordLockWorkspaceTooBroad } from './accordlockWorkspace';

export interface FileReadResult {
  file: string;
  filePath: string;
  error: string | null;
  found: boolean;
}

interface FileAccessRequestProvenance {
  isRegisteredWindow: boolean;
  isMainFrame: boolean;
  rendererUrl: string;
}

export const MAX_DIRECTORY_ENTRIES = 2048;
export const MAX_DIRECTORY_OUTPUT_BYTES = 256 * 1024;
export const MAX_NATIVE_SAVE_BYTES = 1024 * 1024;
export const MAX_AUDIT_SAVE_BYTES = 8 * 1024 * 1024;
export const MAX_GOOSEHINTS_BYTES = 256 * 1024;

const MAX_PATH_BYTES = 4096;
const MAX_EXTENSION_BYTES = 64;

export interface NativeRecipeSaveRequest {
  suggestedName: string;
  content: string;
}

export interface NativeAuditSaveRequest {
  suggestedName: string;
  content: string;
}

export interface NativeSaveDialogResult {
  canceled: boolean;
  filePath?: string;
}

export interface NativeRecipeSaveResult {
  canceled: boolean;
  filePath?: string;
  saved: boolean;
}

export interface NativeWorkspaceDialogResult {
  canceled: boolean;
  filePaths: string[];
}

export interface NativeWorkspaceSelectionResult {
  canceled: boolean;
  directory?: string;
}

type NativeSaveDialog = (suggestedName: string) => Promise<NativeSaveDialogResult>;
type NativeWorkspaceDialog = (defaultPath: string) => Promise<NativeWorkspaceDialogResult>;

export function isAppRendererUrl(rendererUrl: string, expectedUrl: URL): boolean {
  try {
    const actual = new URL(rendererUrl);
    if (expectedUrl.protocol === 'file:') {
      return (
        actual.protocol === 'file:' &&
        actual.host === expectedUrl.host &&
        actual.pathname === expectedUrl.pathname
      );
    }
    return actual.origin === expectedUrl.origin && actual.pathname === expectedUrl.pathname;
  } catch {
    return false;
  }
}

export function isAuthorizedFileAccessRequest(
  provenance: FileAccessRequestProvenance,
  expectedUrl: URL
): boolean {
  return (
    provenance.isRegisteredWindow &&
    provenance.isMainFrame &&
    isAppRendererUrl(provenance.rendererUrl, expectedUrl)
  );
}

function isMissingFile(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'ENOENT'
  );
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function isWithinDirectory(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === '' ||
    (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function hasTraversalComponent(value: string): boolean {
  return value.split(/[\\/]/u).some((component) => component === '..');
}

function validateRequestedDirectory(requestedPath: unknown): asserts requestedPath is string {
  if (
    typeof requestedPath !== 'string' ||
    requestedPath.length === 0 ||
    requestedPath.includes('\0') ||
    byteLength(requestedPath) > MAX_PATH_BYTES ||
    hasTraversalComponent(requestedPath)
  ) {
    throw new Error('The requested directory is invalid');
  }
}

function validateExtension(extension: unknown): asserts extension is string | undefined {
  if (extension === undefined) {
    return;
  }
  if (
    typeof extension !== 'string' ||
    extension.includes('\0') ||
    extension.includes('/') ||
    extension.includes('\\') ||
    byteLength(extension) > MAX_EXTENSION_BYTES
  ) {
    throw new Error('The requested file extension is invalid');
  }
}

function validateNativeSaveRequest(request: unknown): asserts request is NativeRecipeSaveRequest {
  if (typeof request !== 'object' || request === null) {
    throw new Error('The native save request is invalid');
  }
  const candidate = request as Partial<NativeRecipeSaveRequest>;
  if (
    typeof candidate.suggestedName !== 'string' ||
    candidate.suggestedName.length === 0 ||
    candidate.suggestedName !== path.basename(candidate.suggestedName) ||
    byteLength(candidate.suggestedName) > 128 ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._ -]*\.(?:yaml|yml)$/u.test(candidate.suggestedName)
  ) {
    throw new Error('The suggested recipe filename is invalid');
  }
  if (
    typeof candidate.content !== 'string' ||
    byteLength(candidate.content) > MAX_NATIVE_SAVE_BYTES
  ) {
    throw new Error('The recipe export exceeds the safe size limit');
  }
}

function validateNativeAuditSaveRequest(
  request: unknown
): asserts request is NativeAuditSaveRequest {
  if (typeof request !== 'object' || request === null) {
    throw new Error('The audit save request is invalid');
  }
  const candidate = request as Partial<NativeAuditSaveRequest>;
  if (
    typeof candidate.suggestedName !== 'string' ||
    candidate.suggestedName.length === 0 ||
    candidate.suggestedName !== path.basename(candidate.suggestedName) ||
    byteLength(candidate.suggestedName) > 128 ||
    !/^[a-zA-Z0-9][a-zA-Z0-9._ -]*\.(?:json|md)$/u.test(candidate.suggestedName)
  ) {
    throw new Error('The suggested audit filename is invalid');
  }
  if (
    typeof candidate.content !== 'string' ||
    byteLength(candidate.content) > MAX_AUDIT_SAVE_BYTES
  ) {
    throw new Error('The audit export exceeds the safe size limit');
  }
}

function isSameOpenedFile(expected: Stats, opened: Stats): boolean {
  if (expected.ino !== opened.ino) {
    return false;
  }
  if (expected.dev === opened.dev) {
    return true;
  }

  // On Windows, Node can report `dev === 0` for path-based lstat while
  // FileHandle.stat reports the volume identifier for the same NTFS file.
  // Retain the file-index check and require a second stable identity field;
  // any nonzero device disagreement still fails closed.
  return (
    process.platform === 'win32' &&
    expected.ino !== 0 &&
    (expected.dev === 0 || opened.dev === 0) &&
    Number.isFinite(expected.birthtimeMs) &&
    expected.birthtimeMs === opened.birthtimeMs
  );
}

async function writeNativeSelection(filePath: string, content: string): Promise<void> {
  if (
    typeof filePath !== 'string' ||
    !path.isAbsolute(filePath) ||
    filePath.includes('\0') ||
    byteLength(filePath) > MAX_PATH_BYTES
  ) {
    throw new Error('The native save dialog returned an invalid path');
  }

  const noFollow = process.platform === 'win32' ? 0 : fsConstants.O_NOFOLLOW;
  const nonBlocking = process.platform === 'win32' ? 0 : fsConstants.O_NONBLOCK;
  let metadata: Stats;
  try {
    metadata = await fs.lstat(filePath);
  } catch (error) {
    if (!isMissingFile(error)) {
      throw error;
    }
    const handle = await fs.open(
      filePath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow,
      0o600
    );
    try {
      const openedMetadata = await handle.stat();
      if (!openedMetadata.isFile() || openedMetadata.nlink !== 1) {
        throw new Error('The selected destination is not a regular file');
      }
      await handle.writeFile(content, 'utf8');
    } finally {
      await handle.close();
    }
    return;
  }

  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
    throw new Error('The selected destination is not a regular file');
  }

  const handle = await fs.open(filePath, fsConstants.O_WRONLY | noFollow | nonBlocking);
  try {
    const openedMetadata = await handle.stat();
    if (
      !openedMetadata.isFile() ||
      openedMetadata.nlink !== 1 ||
      !isSameOpenedFile(metadata, openedMetadata)
    ) {
      throw new Error('The selected destination changed while it was being opened');
    }
    await handle.truncate(0);
    await handle.writeFile(content, 'utf8');
  } finally {
    await handle.close();
  }
}

async function canonicalNativeDirectory(filePath: unknown): Promise<string> {
  if (
    typeof filePath !== 'string' ||
    !path.isAbsolute(filePath) ||
    filePath.includes('\0') ||
    byteLength(filePath) > MAX_PATH_BYTES
  ) {
    throw new Error('The native directory dialog returned an invalid path');
  }

  const resolvedPath = path.resolve(filePath);
  const selectedMetadata = await fs.lstat(resolvedPath, { bigint: true });
  if (!selectedMetadata.isDirectory() || selectedMetadata.isSymbolicLink()) {
    throw new Error('The selected workspace is not a regular directory');
  }

  const canonicalPath = await fs.realpath(resolvedPath);
  const canonicalMetadata = await fs.lstat(canonicalPath, { bigint: true });
  if (
    !canonicalMetadata.isDirectory() ||
    canonicalMetadata.isSymbolicLink() ||
    canonicalMetadata.dev !== selectedMetadata.dev ||
    canonicalMetadata.ino !== selectedMetadata.ino
  ) {
    throw new Error('The selected workspace changed while it was being authorized');
  }
  return canonicalPath;
}

function missingFile(filePath: string): FileReadResult {
  return { file: '', filePath, error: null, found: false };
}

function failedRead(filePath: string, message: string): FileReadResult {
  return { file: '', filePath, error: message, found: false };
}

type WorkingDirectoryBinding =
  | { status: 'ready'; path: string; dev: bigint; ino: bigint }
  | { status: 'missing'; path: string }
  | { status: 'error'; path: string };

export class DesktopFileAccess {
  private readonly workingDirectories = new Map<number, WorkingDirectoryBinding>();
  private readonly nativeDialogsInProgress = new Set<number>();

  private bindingForWindow(windowId: number): WorkingDirectoryBinding {
    const binding = this.workingDirectories.get(windowId);
    if (!binding) {
      throw new Error('This window is not authorized to access the local workspace');
    }
    return binding;
  }

  private async bindingMatchesDirectory(binding: WorkingDirectoryBinding): Promise<boolean> {
    if (binding.status !== 'ready') {
      return false;
    }
    try {
      const metadata = await fs.lstat(binding.path, { bigint: true });
      return (
        metadata.isDirectory() &&
        !metadata.isSymbolicLink() &&
        metadata.dev === binding.dev &&
        metadata.ino === binding.ino
      );
    } catch {
      return false;
    }
  }

  async bindWindow(
    windowId: number,
    workingDirectory: string,
    protectedPaths: readonly string[] = []
  ): Promise<void> {
    const resolvedPath = path.resolve(workingDirectory);
    try {
      const canonicalPath = await fs.realpath(resolvedPath);
      const metadata = await fs.lstat(canonicalPath, { bigint: true });
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw new Error('Working directory is not a regular directory');
      }
      if (isAccordLockWorkspaceTooBroad(canonicalPath, protectedPaths)) {
        throw new Error('Working directory is too broad for AccordLock');
      }
      this.workingDirectories.set(windowId, {
        status: 'ready',
        path: canonicalPath,
        dev: metadata.dev,
        ino: metadata.ino,
      });
    } catch (error) {
      this.workingDirectories.set(windowId, {
        status: isMissingFile(error) ? 'missing' : 'error',
        path: resolvedPath,
      });
    }
  }

  unbindWindow(windowId: number): void {
    this.workingDirectories.delete(windowId);
  }

  /**
   * Returns the still-valid canonical workspace bound by the main process.
   * On Windows, Rust's `std::fs::canonicalize` uses the namespaced form, so
   * the control-plane binding must use that same representation.
   */
  async authorizedWorkingDirectory(windowId: number): Promise<string> {
    const binding = this.bindingForWindow(windowId);
    if (binding.status !== 'ready' || !(await this.bindingMatchesDirectory(binding))) {
      throw new Error('The trusted working directory binding is unavailable or changed');
    }
    return process.platform === 'win32' ? path.toNamespacedPath(binding.path) : binding.path;
  }

  /** Returns the canonical, non-namespaced path for trusted Desktop-only operations. */
  async authorizedDesktopWorkingDirectory(windowId: number): Promise<string> {
    const binding = this.bindingForWindow(windowId);
    if (binding.status !== 'ready' || !(await this.bindingMatchesDirectory(binding))) {
      throw new Error('The trusted working directory binding is unavailable or changed');
    }
    return binding.path;
  }

  async listFiles(
    windowId: number,
    requestedPath: unknown,
    extension?: unknown
  ): Promise<string[]> {
    validateRequestedDirectory(requestedPath);
    validateExtension(extension);

    const binding = this.bindingForWindow(windowId);
    if (binding.status !== 'ready' || !(await this.bindingMatchesDirectory(binding))) {
      throw new Error('The trusted working directory binding is unavailable or changed');
    }

    const resolvedPath = path.isAbsolute(requestedPath)
      ? path.resolve(requestedPath)
      : path.resolve(binding.path, requestedPath);
    if (!isWithinDirectory(binding.path, resolvedPath)) {
      throw new Error('The requested directory is outside the authorized workspace');
    }

    const requestedMetadata = await fs.lstat(resolvedPath, { bigint: true });
    if (requestedMetadata.isSymbolicLink()) {
      throw new Error('Refusing to list a symbolic-link directory');
    }

    const canonicalPath = await fs.realpath(resolvedPath);
    if (!isWithinDirectory(binding.path, canonicalPath)) {
      throw new Error('The requested directory resolves outside the authorized workspace');
    }

    const canonicalMetadata = await fs.lstat(canonicalPath, { bigint: true });
    if (
      !canonicalMetadata.isDirectory() ||
      canonicalMetadata.isSymbolicLink() ||
      canonicalMetadata.dev !== binding.dev
    ) {
      throw new Error('The requested path is not a regular directory');
    }

    const names: string[] = [];
    let scannedEntries = 0;
    let outputBytes = 0;
    const directory = await fs.opendir(canonicalPath);
    try {
      for await (const entry of directory) {
        scannedEntries += 1;
        if (scannedEntries > MAX_DIRECTORY_ENTRIES) {
          throw new Error('The directory exceeds the safe entry limit');
        }
        if (extension !== undefined && !entry.name.endsWith(extension)) {
          continue;
        }
        outputBytes += byteLength(entry.name);
        if (outputBytes > MAX_DIRECTORY_OUTPUT_BYTES) {
          throw new Error('The directory listing exceeds the safe output limit');
        }
        names.push(entry.name);
      }
    } finally {
      await directory.close().catch(() => undefined);
    }

    const finalMetadata = await fs.lstat(canonicalPath, { bigint: true });
    if (
      !finalMetadata.isDirectory() ||
      finalMetadata.isSymbolicLink() ||
      finalMetadata.dev !== canonicalMetadata.dev ||
      finalMetadata.ino !== canonicalMetadata.ino ||
      !(await this.bindingMatchesDirectory(binding))
    ) {
      throw new Error('The directory changed while it was being listed');
    }

    return names;
  }

  /**
   * Performs exactly one native picker selection and immediately consumes it.
   * No path, grant, or reusable capability crosses the renderer boundary.
   */
  async saveRecipeWithNativeDialog(
    windowId: number,
    request: unknown,
    showDialog: NativeSaveDialog
  ): Promise<NativeRecipeSaveResult> {
    validateNativeSaveRequest(request);
    const binding = this.bindingForWindow(windowId);
    if (binding.status !== 'ready' || !(await this.bindingMatchesDirectory(binding))) {
      throw new Error('The trusted working directory binding is unavailable or changed');
    }
    if (this.nativeDialogsInProgress.has(windowId)) {
      throw new Error('A native file dialog is already active for this window');
    }

    this.nativeDialogsInProgress.add(windowId);
    try {
      const selection = await showDialog(request.suggestedName);
      if (selection.canceled || !selection.filePath) {
        return { canceled: true, saved: false };
      }
      if (this.workingDirectories.get(windowId) !== binding) {
        throw new Error('The window authorization changed while the save dialog was open');
      }
      await writeNativeSelection(selection.filePath, request.content);
      return { canceled: false, filePath: selection.filePath, saved: true };
    } finally {
      this.nativeDialogsInProgress.delete(windowId);
    }
  }

  /** Saves one bounded audit export chosen through the trusted native dialog. */
  async saveAuditWithNativeDialog(
    windowId: number,
    request: unknown,
    showDialog: NativeSaveDialog
  ): Promise<NativeRecipeSaveResult> {
    validateNativeAuditSaveRequest(request);
    const binding = this.bindingForWindow(windowId);
    if (binding.status !== 'ready' || !(await this.bindingMatchesDirectory(binding))) {
      throw new Error('The trusted working directory binding is unavailable or changed');
    }
    if (this.nativeDialogsInProgress.has(windowId)) {
      throw new Error('A native file dialog is already active for this window');
    }

    this.nativeDialogsInProgress.add(windowId);
    try {
      const selection = await showDialog(request.suggestedName);
      if (selection.canceled || !selection.filePath) {
        return { canceled: true, saved: false };
      }
      if (this.workingDirectories.get(windowId) !== binding) {
        throw new Error('The window authorization changed while the save dialog was open');
      }
      await writeNativeSelection(selection.filePath, request.content);
      return { canceled: false, filePath: selection.filePath, saved: true };
    } finally {
      this.nativeDialogsInProgress.delete(windowId);
    }
  }

  /** Selects one canonical workspace through a trusted, non-replayable native dialog. */
  async selectWorkspaceWithNativeDialog(
    windowId: number,
    showDialog: NativeWorkspaceDialog
  ): Promise<NativeWorkspaceSelectionResult> {
    const binding = this.bindingForWindow(windowId);
    if (binding.status !== 'ready' || !(await this.bindingMatchesDirectory(binding))) {
      throw new Error('The trusted working directory binding is unavailable or changed');
    }
    if (this.nativeDialogsInProgress.has(windowId)) {
      throw new Error('A native file dialog is already active for this window');
    }

    this.nativeDialogsInProgress.add(windowId);
    try {
      const selection = await showDialog(binding.path);
      if (selection.canceled || selection.filePaths.length === 0) {
        return { canceled: true };
      }
      if (
        selection.filePaths.length !== 1 ||
        this.workingDirectories.get(windowId) !== binding ||
        !(await this.bindingMatchesDirectory(binding))
      ) {
        throw new Error('The window authorization changed while the directory dialog was open');
      }
      return {
        canceled: false,
        directory: await canonicalNativeDirectory(selection.filePaths[0]),
      };
    } finally {
      this.nativeDialogsInProgress.delete(windowId);
    }
  }

  async readGoosehints(windowId: number): Promise<FileReadResult> {
    const binding = this.bindingForWindow(windowId);
    const filePath = path.join(binding.path, '.goosehints');
    if (binding.status === 'missing') {
      return missingFile(filePath);
    }
    if (binding.status === 'error') {
      return failedRead(filePath, 'Unable to resolve the working directory');
    }
    if (!(await this.bindingMatchesDirectory(binding))) {
      return failedRead(filePath, 'The working directory changed after it was authorized');
    }

    try {
      const metadata = await fs.lstat(filePath);
      if (metadata.isSymbolicLink()) {
        return failedRead(filePath, 'Refusing to read a symbolic link as .goosehints');
      }
      if (!metadata.isFile() || metadata.nlink !== 1) {
        return failedRead(filePath, '.goosehints is not a regular file');
      }
      if (metadata.size > MAX_GOOSEHINTS_BYTES) {
        return failedRead(filePath, '.goosehints exceeds the safe size limit');
      }

      const canonicalFilePath = await fs.realpath(filePath);
      if (path.dirname(canonicalFilePath) !== binding.path) {
        return failedRead(filePath, '.goosehints resolves outside the working directory');
      }

      const noFollow = process.platform === 'win32' ? 0 : fsConstants.O_NOFOLLOW;
      const nonBlocking = process.platform === 'win32' ? 0 : fsConstants.O_NONBLOCK;
      const handle = await fs.open(
        canonicalFilePath,
        fsConstants.O_RDONLY | noFollow | nonBlocking
      );
      try {
        const openedMetadata = await handle.stat();
        if (
          !openedMetadata.isFile() ||
          openedMetadata.nlink !== 1 ||
          openedMetadata.size > MAX_GOOSEHINTS_BYTES
        ) {
          return failedRead(filePath, '.goosehints is not a regular file');
        }
        if (!isSameOpenedFile(metadata, openedMetadata)) {
          return failedRead(filePath, '.goosehints changed while it was being opened');
        }
        if (!(await this.bindingMatchesDirectory(binding))) {
          return failedRead(filePath, 'The working directory changed after it was authorized');
        }
        const buffer = Buffer.alloc(MAX_GOOSEHINTS_BYTES + 1);
        let bytesRead = 0;
        while (bytesRead < buffer.length) {
          const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, null);
          if (result.bytesRead === 0) {
            break;
          }
          bytesRead += result.bytesRead;
        }
        if (bytesRead > MAX_GOOSEHINTS_BYTES) {
          return failedRead(filePath, '.goosehints exceeds the safe size limit');
        }
        if (!(await this.bindingMatchesDirectory(binding))) {
          return failedRead(filePath, 'The working directory changed after it was authorized');
        }
        return {
          file: buffer.subarray(0, bytesRead).toString('utf8'),
          filePath,
          error: null,
          found: true,
        };
      } finally {
        await handle.close();
      }
    } catch (error) {
      if (isMissingFile(error)) {
        return missingFile(filePath);
      }
      return failedRead(filePath, 'Unable to read .goosehints');
    }
  }

  async writeGoosehints(windowId: number, content: string): Promise<boolean> {
    const binding = this.bindingForWindow(windowId);
    if (
      binding.status !== 'ready' ||
      typeof content !== 'string' ||
      byteLength(content) > MAX_GOOSEHINTS_BYTES
    ) {
      return false;
    }
    if (!(await this.bindingMatchesDirectory(binding))) {
      return false;
    }

    const filePath = path.join(binding.path, '.goosehints');
    const noFollow = process.platform === 'win32' ? 0 : fsConstants.O_NOFOLLOW;
    const nonBlocking = process.platform === 'win32' ? 0 : fsConstants.O_NONBLOCK;
    try {
      let metadata: Stats;
      try {
        metadata = await fs.lstat(filePath);
      } catch (error) {
        if (!isMissingFile(error)) {
          return false;
        }
        if (!(await this.bindingMatchesDirectory(binding))) {
          return false;
        }

        const handle = await fs.open(
          filePath,
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollow,
          0o600
        );
        try {
          const openedMetadata = await handle.stat();
          if (!openedMetadata.isFile() || openedMetadata.nlink !== 1) {
            return false;
          }
          if (!(await this.bindingMatchesDirectory(binding))) {
            return false;
          }
          await handle.writeFile(content, 'utf8');
          return true;
        } finally {
          await handle.close();
        }
      }

      if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1) {
        return false;
      }

      const handle = await fs.open(filePath, fsConstants.O_WRONLY | noFollow | nonBlocking);
      try {
        const openedMetadata = await handle.stat();
        if (
          !openedMetadata.isFile() ||
          openedMetadata.nlink !== 1 ||
          !isSameOpenedFile(metadata, openedMetadata)
        ) {
          return false;
        }
        if (!(await this.bindingMatchesDirectory(binding))) {
          return false;
        }
        await handle.truncate(0);
        await handle.writeFile(content, 'utf8');
        return true;
      } finally {
        await handle.close();
      }
    } catch {
      return false;
    }
  }
}

export async function readSelectedRecipe(filePath: string): Promise<FileReadResult> {
  const extension = path.extname(filePath).toLowerCase();
  if (extension !== '.yaml' && extension !== '.yml') {
    return failedRead(filePath, 'The selected recipe must be a YAML file');
  }

  try {
    const nonBlocking = process.platform === 'win32' ? 0 : fsConstants.O_NONBLOCK;
    const handle = await fs.open(filePath, fsConstants.O_RDONLY | nonBlocking);
    try {
      const metadata = await handle.stat();
      if (!metadata.isFile()) {
        return failedRead(filePath, 'The selected recipe is not a regular file');
      }
      return {
        file: await handle.readFile('utf8'),
        filePath,
        error: null,
        found: true,
      };
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (isMissingFile(error)) {
      return missingFile(filePath);
    }
    return failedRead(filePath, 'Unable to read the selected recipe');
  }
}
