import {NativeModules, NativeEventEmitter} from 'react-native';
const module = NativeModules.XopRasp;
export const getStatus = () => module.getStatus();
export const getThreatReports = () => module.getThreatReports();
export const onOperationBlocked = callback =>
  new NativeEventEmitter(module).addListener('XopOperationBlocked', callback);
