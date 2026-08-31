import path from 'node:path';
import { app } from 'electron';

app.setName('AccordLock');

app.setAppLogsPath(path.join(app.getPath('userData'), 'logs'));
const accordLockLogsDirectory = app.getPath('logs');
app.commandLine.appendSwitch('log-file', path.join(accordLockLogsDirectory, 'chromium.log'));
