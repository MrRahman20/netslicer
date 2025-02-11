export interface DeviceInfo {
  ip: string;
  mac: string;
  hostname: string;
  os: string;
  status: 'active' | 'inactive';
  lastSeen?: number;
}

export interface ScanResult {
  devices: DeviceInfo[];
  scanTime: number;
  error?: string;
}

export interface NetworkMonitorConfig {
  ipRange: string;
  scanInterval: number;
  enableOsDetection: boolean;
  enablePortScanning: boolean;
}

export type MonitorCallback = (message: string) => void;

export interface SecurityThreat {
  type: 'port_scan' | 'suspicious_traffic' | 'arp_spoofing';
  sourceIp: string;
  timestamp: number;
  description: string;
  severity: 'low' | 'medium' | 'high';
}