import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

import * as crypto from 'crypto';

export class IkoulaApiDedicatedServer implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula API Dedicated Server',
		name: 'ikoulaApiDedicatedServer',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["resource"] + ": " + $parameter["operation"]}}',
		description: 'Interact with Ikoula Dedicated Server API. Developed by Ascenzia - www.ascenzia.fr',
		defaults: {
			name: 'Ikoula API Dedicated Server',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				name: 'ikoulaApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Automatic Power Control',
						value: 'automaticPowerControl',
						description: 'Manage APC reboots',
					},
					{
						name: 'Dedicated Server',
						value: 'dedicatedServer',
						description: 'Manage dedicated servers',
					},
					{
						name: 'DNS Secondary',
						value: 'dnsSecondary',
						description: 'Manage secondary DNS',
					},
					{
						name: 'Network Boot',
						value: 'networkBoot',
						description: 'Manage network boot (netboot)',
					},
					{
						name: 'Network Diagnostic',
						value: 'networkDiagnostic',
						description: 'Manage network diagnostics',
					},
					{
						name: 'Remote Access Control',
						value: 'remoteAccessControl',
						description: 'Manage remote access control',
					},
					{
						name: 'Reset',
						value: 'reset',
						description: 'Manage server reset (RAZ)',
					},
					{
						name: 'Reverse DN',
						value: 'reverseDns',
						description: 'Manage reverse DNS',
					},
					{
						name: 'Security Scan',
						value: 'securityScan',
						description: 'Manage security scans',
					},
				],
				default: 'dedicatedServer',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['dedicatedServer'],
					},
				},
				options: [
					{
						name: 'List Servers',
						value: 'listServers',
						description: 'Get the list of dedicated servers',
						action: 'List servers a dedicated server',
					},
					{
						name: 'Get Server Details',
						value: 'getServerDetails',
						description: 'Get details for a dedicated server subscription',
						action: 'Get server details a dedicated server',
					},
					{
						name: 'Manage Network',
						value: 'manageNetwork',
						description: 'Manage the network of the dedicated server',
						action: 'Manage network a dedicated server',
					},
				],
				default: 'listServers',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['remoteAccessControl'],
					},
				},
				options: [
					{
						name: 'Request Access',
						value: 'requestAccess',
						description: 'Request a Remote Access Control NAT access',
						action: 'Request access a remote access control',
					},
					{
						name: 'Renew Access',
						value: 'renewAccess',
						description: 'Renew Remote Access Control',
						action: 'Renew access a remote access control',
					},
					{
						name: 'Delete Access',
						value: 'deleteAccess',
						description: 'Delete Remote Access Control',
						action: 'Delete access a remote access control',
					},
				],
				default: 'requestAccess',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['automaticPowerControl'],
					},
				},
				options: [
					{
						name: 'List Reboots',
						value: 'listReboots',
						description: 'Get the list of APC reboots',
						action: 'List reboots an automatic power control',
					},
					{
						name: 'Request Reboot',
						value: 'requestReboot',
						description: 'Ask for an APC reboot',
						action: 'Request reboot an automatic power control',
					},
					{
						name: 'Get Reboot Status',
						value: 'getRebootStatus',
						description: 'Get the status of an APC reboot',
						action: 'Get reboot status an automatic power control',
					},
					{
						name: 'Abort Reboot',
						value: 'abortReboot',
						description: 'Abort an APC reboot',
						action: 'Abort reboot an automatic power control',
					},
				],
				default: 'listReboots',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['networkDiagnostic'],
					},
				},
				options: [
					{
						name: 'List Diagnostics',
						value: 'listDiagnostics',
						description: 'Get the list of net diagnostics',
						action: 'List diagnostics a network diagnostic',
					},
					{
						name: 'Request Diagnostic',
						value: 'requestDiagnostic',
						description: 'Ask for a net diagnostic',
						action: 'Request diagnostic a network diagnostic',
					},
					{
						name: 'Get Diagnostic Status',
						value: 'getDiagnosticStatus',
						description: 'Get the status of a net diagnostic',
						action: 'Get diagnostic status a network diagnostic',
					},
					{
						name: 'Abort Diagnostic',
						value: 'abortDiagnostic',
						description: 'Abort a net diagnostic',
						action: 'Abort diagnostic a network diagnostic',
					},
				],
				default: 'listDiagnostics',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['networkBoot'],
					},
				},
				options: [
					{
						name: 'List Netboots',
						value: 'listNetboots',
						description: 'Get the list of netboots',
						action: 'List netboots a network boot',
					},
					{
						name: 'Request Netboot',
						value: 'requestNetboot',
						description: 'Request a netboot',
						action: 'Request netboot a network boot',
					},
					{
						name: 'Get Netboot Status',
						value: 'getNetbootStatus',
						description: 'Get the status of a netboot',
						action: 'Get netboot status a network boot',
					},
					{
						name: 'Cancel Netboot',
						value: 'cancelNetboot',
						description: 'Cancel a netboot request',
						action: 'Cancel netboot a network boot',
					},
				],
				default: 'listNetboots',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['reset'],
					},
				},
				options: [
					{
						name: 'List Resets',
						value: 'listResets',
						description: 'Get the list of reset requests',
						action: 'List resets a reset',
					},
					{
						name: 'Request Reset',
						value: 'requestReset',
						description: 'Ask for a reset of the server',
						action: 'Request reset a reset',
					},
					{
						name: 'Get Reset Details',
						value: 'getResetDetails',
						description: 'Get the details of a reset request',
						action: 'Get reset details a reset',
					},
					{
						name: 'Cancel Reset',
						value: 'cancelReset',
						description: 'Cancel a reset request if possible',
						action: 'Cancel reset a reset',
					},
				],
				default: 'listResets',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['dnsSecondary'],
					},
				},
				options: [
					{
						name: 'List Secondary DNS',
						value: 'listSecondaryDns',
						description: 'List secondary DNS entries',
						action: 'List secondary dns a dns secondary',
					},
					{
						name: 'Add Secondary DNS',
						value: 'addSecondaryDns',
						description: 'Add a secondary DNS entry',
						action: 'Add secondary dns a dns secondary',
					},
					{
						name: 'Modify Secondary DNS',
						value: 'modifySecondaryDns',
						description: 'Modify a secondary DNS entry',
						action: 'Modify secondary dns a dns secondary',
					},
					{
						name: 'Delete Secondary DNS',
						value: 'deleteSecondaryDns',
						description: 'Delete a secondary DNS entry',
						action: 'Delete secondary dns a dns secondary',
					},
				],
				default: 'listSecondaryDns',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['reverseDns'],
					},
				},
				options: [
					{
						name: 'List Reverse DNS',
						value: 'listReverseDns',
						description: 'List reverse DNS entries',
						action: 'List reverse dns a reverse dns',
					},
					{
						name: 'Modify Reverse DNS',
						value: 'modifyReverseDns',
						description: 'Modify the reverse DNS',
						action: 'Modify reverse dns a reverse dns',
					},
				],
				default: 'listReverseDns',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['securityScan'],
					},
				},
				options: [
					{
						name: 'List Security Scans',
						value: 'listSecurityScans',
						description: 'List all security scans',
						action: 'List security scans a security scan',
					},
					{
						name: 'Request Security Scan',
						value: 'requestSecurityScan',
						description: 'Ask for a security scan',
						action: 'Request security scan a security scan',
					},
					{
						name: 'Get Scan Results',
						value: 'getScanResults',
						description: 'Get the result of a security scan',
						action: 'Get scan results a security scan',
					},
					{
						name: 'Cancel Security Scan',
						value: 'cancelSecurityScan',
						description: 'Cancel a security scan',
						action: 'Cancel security scan a security scan',
					},
				],
				default: 'listSecurityScans',
			},
			{
				displayName: 'Server IP',
				name: 'serverIp',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['dedicatedServer', 'remoteAccessControl', 'automaticPowerControl', 'networkDiagnostic', 'networkBoot', 'reset', 'dnsSecondary', 'reverseDns', 'securityScan'],
						operation: ['getServerDetails', 'manageNetwork', 'requestAccess', 'renewAccess', 'deleteAccess', 'listReboots', 'requestReboot', 'getRebootStatus', 'abortReboot', 'listDiagnostics', 'requestDiagnostic', 'getDiagnosticStatus', 'abortDiagnostic', 'listNetboots', 'requestNetboot', 'getNetbootStatus', 'cancelNetboot', 'listResets', 'requestReset', 'getResetDetails', 'cancelReset', 'listSecondaryDns', 'addSecondaryDns', 'modifySecondaryDns', 'deleteSecondaryDns', 'listReverseDns', 'modifyReverseDns', 'listSecurityScans', 'requestSecurityScan', 'getScanResults', 'cancelSecurityScan'],
					},
				},
				default: '',
				description: 'The server IP address',
			},
			{
				displayName: 'Action',
				name: 'action',
				type: 'options',
				required: true,
				displayOptions: {
					show: {
						resource: ['dedicatedServer'],
						operation: ['manageNetwork'],
					},
				},
				options: [
					{
						name: 'Turn On',
						value: 'ON',
						action: 'Turn on a dedicated server',
					},
					{
						name: 'Turn Off',
						value: 'OFF',
						action: 'Turn off a dedicated server',
					},
				],
				default: 'ON',
			},
			{
				displayName: 'Source IP',
				name: 'ipSource',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['remoteAccessControl'],
						operation: ['requestAccess'],
					},
				},
				default: '',
				description: 'The source IP address for Remote Access Control',
			},
			{
				displayName: 'Tempo',
				name: 'tempo',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['automaticPowerControl'],
						operation: ['requestReboot'],
					},
				},
				default: '',
				description: 'The tempo parameter for APC reboot (optional)',
			},
			{
				displayName: 'Reboot ID',
				name: 'rebootId',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['automaticPowerControl'],
						operation: ['getRebootStatus', 'abortReboot'],
					},
				},
				default: '',
				description: 'The ID of the APC reboot',
			},
			{
				displayName: 'Netdiag ID',
				name: 'netdiagId',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['networkDiagnostic'],
						operation: ['getDiagnosticStatus', 'abortDiagnostic'],
					},
				},
				default: '',
				description: 'The ID of the network diagnostic',
			},
			{
				displayName: 'Netboot ID',
				name: 'netbootId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['networkBoot'],
						operation: ['getNetbootStatus', 'cancelNetboot'],
					},
				},
				default: 0,
				description: 'The ID of the netboot',
			},
			{
				displayName: 'RAZ ID',
				name: 'razId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['reset'],
						operation: ['getResetDetails', 'cancelReset'],
					},
				},
				default: 0,
				description: 'The ID of the reset request',
			},
			{
				displayName: 'DNS Name',
				name: 'dnsName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['dnsSecondary'],
						operation: ['addSecondaryDns', 'modifySecondaryDns'],
					},
				},
				default: '',
				description: 'The DNS name for the secondary DNS entry',
			},
			{
				displayName: 'DNS ID',
				name: 'dnsId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['dnsSecondary'],
						operation: ['modifySecondaryDns', 'deleteSecondaryDns'],
					},
				},
				default: 0,
				description: 'The ID of the DNS secondary entry',
			},
			{
				displayName: 'Reverse DNS ID',
				name: 'reverseDnsId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['reverseDns'],
						operation: ['modifyReverseDns'],
					},
				},
				default: 0,
				description: 'The ID of the reverse DNS entry',
			},
			{
				displayName: 'Scan Date',
				name: 'scanDate',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['securityScan'],
						operation: ['requestSecurityScan'],
					},
				},
				default: '',
				description: 'The date to schedule the scan (optional, format: 0000-00-00 00:00:00)',
			},
			{
				displayName: 'Scan ID',
				name: 'scanId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['securityScan'],
						operation: ['getScanResults', 'cancelSecurityScan'],
					},
				},
				default: 0,
				description: 'The ID of the security scan',
			},
			{
				displayName: 'Cancel Type',
				name: 'cancelType',
				type: 'options',
				required: true,
				displayOptions: {
					show: {
						resource: ['securityScan'],
						operation: ['cancelSecurityScan'],
					},
				},
				options: [
					{
						name: 'Abort Delayed',
						value: 'ABORT_DELAYED',
					},
					{
						name: 'Pause',
						value: 'PAUSE',
					},
					{
						name: 'Restart',
						value: 'RESTART',
					},
					{
						name: 'Restart Delayed',
						value: 'RESTART_DELAYED',
					},
					{
						name: 'Stop',
						value: 'STOP',
					},
					{
						name: 'Update Delayed',
						value: 'UPDATE_DELAYED',
					},
				],
				default: 'STOP',
				description: 'The type of cancellation action',
			},
			{
				displayName: 'New Date',
				name: 'newDate',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['securityScan'],
						operation: ['cancelSecurityScan'],
					},
				},
				default: '',
				description: 'New date for the scan (optional, format: 0000-00-00 00:00:00)',
			},
			{
				displayName: 'Response Format',
				name: 'format',
				type: 'options',
				options: [
					{
						name: 'JSON',
						value: 'json',
					},
					{
						name: 'XML',
						value: 'xml',
					},
				],
				default: 'json',
				description: 'The format of the API response',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const credentials = await this.getCredentials('ikoulaApi');

		if (!credentials) {
			throw new NodeOperationError(this.getNode(), 'No credentials provided!');
		}

		const email = credentials.email as string;
		const password = credentials.password as string;
		const apiUrl = (credentials.apiUrl as string) || 'https://api.ikoula.com';

		// Using static imports for Node.js modules

		// Embedded RSA public key (instead of reading from file)
		const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr6aXKbRJ+LdqhfNV4rxm
qEFtIuFzk2Xve4Hr/Z3mIDda5A2mJkv5B3rF1bKzP5FzXmLFf14jYgwAk50qY9K1
IEa+aSOjLhs4hEijg6yIru8wHu4UQbR9kkP/zSfkD9o58a26m8IgOr9WODtRhmSV
Y7zMZpsec2Z9hRk5cJYzpiC9d2UkU0no3fouCeLrg2VmhXcWM/KR/t1StTJFiJLI
g3lE+qjvdipuMN8BbA5dqPlugERiW9tvD3hMfeB9wl30kdMza+d3E8uXxuIDGIZd
npCxjWrFGSlFCIgnSfYXBtCKyDcsBcKGH1V7ks4AkzWhxesMyivVDuRZa6jf5E5U
XwIDAQAB
-----END PUBLIC KEY-----`;

		// Encrypt password with RSA public key
		const encryptPassword = (password: string, publicKey: string): string => {
			const buffer = Buffer.from(password, 'utf8');
			const encrypted = crypto.publicEncrypt(
				{
					key: publicKey,
					padding: crypto.constants.RSA_PKCS1_PADDING,
				},
				buffer,
			);
			return encrypted.toString('base64');
		};

		const cryptedPassword = encryptPassword(password, publicKey);

		for (let i = 0; i < items.length; i++) {
			try {
				const resource = this.getNodeParameter('resource', i) as string;
				const operation = this.getNodeParameter('operation', i) as string;
				const format = this.getNodeParameter('format', i) as string;

				let endpoint = '';
				let method = 'GET';
				let body: any = undefined;
				const params: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				// Determine the endpoint and method based on resource and operation
				if (resource === 'dedicatedServer') {
					switch (operation) {
						case 'listServers':
							endpoint = '/ds';
							method = 'GET';
							break;
						case 'getServerDetails':
							const serverIpDetails = this.getNodeParameter('serverIp', i) as string;
							endpoint = `/ds/${serverIpDetails}`;
							method = 'GET';
							break;
						case 'manageNetwork':
							const serverIpNetwork = this.getNodeParameter('serverIp', i) as string;
							const action = this.getNodeParameter('action', i) as string;
							endpoint = `/ds/${serverIpNetwork}/network`;
							method = 'PUT';
							body = {
								action: action,
							};
							break;
					}
				} else if (resource === 'remoteAccessControl') {
					const serverIpRac = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'requestAccess':
							const ipSource = this.getNodeParameter('ipSource', i) as string;
							endpoint = `/ds/${serverIpRac}/rac`;
							method = 'PUT';
							body = {
								ip_source: ipSource,
							};
							break;
						case 'renewAccess':
							endpoint = `/ds/${serverIpRac}/rac`;
							method = 'POST';
							break;
						case 'deleteAccess':
							endpoint = `/ds/${serverIpRac}/rac`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'automaticPowerControl') {
					const serverIpApc = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listReboots':
							endpoint = `/ds/${serverIpApc}/apc-reboot`;
							method = 'GET';
							break;
						case 'requestReboot':
							endpoint = `/ds/${serverIpApc}/apc-reboot`;
							method = 'POST';
							const tempo = this.getNodeParameter('tempo', i, '') as string;
							if (tempo) {
								body = {
									tempo: tempo,
								};
							}
							break;
						case 'getRebootStatus':
							const rebootIdStatus = this.getNodeParameter('rebootId', i) as string;
							endpoint = `/ds/${serverIpApc}/apc-reboot/${rebootIdStatus}`;
							method = 'GET';
							break;
						case 'abortReboot':
							const rebootIdAbort = this.getNodeParameter('rebootId', i) as string;
							endpoint = `/ds/${serverIpApc}/apc-reboot/${rebootIdAbort}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'networkDiagnostic') {
					const serverIpNetdiag = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listDiagnostics':
							endpoint = `/ds/${serverIpNetdiag}/netdiag`;
							method = 'GET';
							break;
						case 'requestDiagnostic':
							endpoint = `/ds/${serverIpNetdiag}/netdiag`;
							method = 'POST';
							break;
						case 'getDiagnosticStatus':
							const netdiagIdStatus = this.getNodeParameter('netdiagId', i) as string;
							endpoint = `/ds/${serverIpNetdiag}/netdiag/${netdiagIdStatus}`;
							method = 'GET';
							break;
						case 'abortDiagnostic':
							const netdiagIdAbort = this.getNodeParameter('netdiagId', i) as string;
							endpoint = `/ds/${serverIpNetdiag}/netdiag/${netdiagIdAbort}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'networkBoot') {
					const serverIpNetboot = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listNetboots':
							endpoint = `/ds/${serverIpNetboot}/netboot`;
							method = 'GET';
							break;
						case 'requestNetboot':
							endpoint = `/ds/${serverIpNetboot}/netboot`;
							method = 'POST';
							break;
						case 'getNetbootStatus':
							const netbootIdStatus = this.getNodeParameter('netbootId', i) as number;
							endpoint = `/ds/${serverIpNetboot}/netboot/${netbootIdStatus}`;
							method = 'GET';
							break;
						case 'cancelNetboot':
							const netbootIdCancel = this.getNodeParameter('netbootId', i) as number;
							endpoint = `/ds/${serverIpNetboot}/netboot/${netbootIdCancel}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'reset') {
					const serverIpReset = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listResets':
							endpoint = `/ds/${serverIpReset}/raz`;
							method = 'GET';
							break;
						case 'requestReset':
							endpoint = `/ds/${serverIpReset}/raz`;
							method = 'POST';
							break;
						case 'getResetDetails':
							const razIdDetails = this.getNodeParameter('razId', i) as number;
							endpoint = `/ds/${serverIpReset}/raz/${razIdDetails}`;
							method = 'GET';
							break;
						case 'cancelReset':
							const razIdCancel = this.getNodeParameter('razId', i) as number;
							endpoint = `/ds/${serverIpReset}/raz/${razIdCancel}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'dnsSecondary') {
					const serverIpDns = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listSecondaryDns':
							endpoint = `/ds/${serverIpDns}/dns-sec`;
							method = 'GET';
							break;
						case 'addSecondaryDns':
							const dnsNameAdd = this.getNodeParameter('dnsName', i) as string;
							endpoint = `/ds/${serverIpDns}/dns-sec`;
							method = 'POST';
							body = {
								dns_name: dnsNameAdd,
							};
							break;
						case 'modifySecondaryDns':
							const dnsNameModify = this.getNodeParameter('dnsName', i) as string;
							const dnsIdModify = this.getNodeParameter('dnsId', i) as number;
							endpoint = `/ds/${serverIpDns}/dns-sec/${dnsIdModify}`;
							method = 'PUT';
							body = {
								dns_name: dnsNameModify,
							};
							break;
						case 'deleteSecondaryDns':
							const dnsIdDelete = this.getNodeParameter('dnsId', i) as number;
							endpoint = `/ds/${serverIpDns}/dns-sec/${dnsIdDelete}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'reverseDns') {
					const serverIpReverseDns = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listReverseDns':
							endpoint = `/ds/${serverIpReverseDns}/reverse-dns`;
							method = 'GET';
							break;
						case 'modifyReverseDns':
							const reverseDnsId = this.getNodeParameter('reverseDnsId', i) as number;
							endpoint = `/ds/${serverIpReverseDns}/reverse-dns/${reverseDnsId}`;
							method = 'PUT';
							break;
					}
				} else if (resource === 'securityScan') {
					const serverIpSecurityScan = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listSecurityScans':
							endpoint = `/ds/${serverIpSecurityScan}/security-scan`;
							method = 'GET';
							break;
						case 'requestSecurityScan':
							endpoint = `/ds/${serverIpSecurityScan}/security-scan`;
							method = 'POST';
							const scanDate = this.getNodeParameter('scanDate', i, '') as string;
							if (scanDate) {
								body = {
									scan_date: scanDate,
								};
							}
							break;
						case 'getScanResults':
							const scanIdResults = this.getNodeParameter('scanId', i) as number;
							endpoint = `/ds/${serverIpSecurityScan}/security-scan/${scanIdResults}`;
							method = 'GET';
							break;
						case 'cancelSecurityScan':
							const scanIdCancel = this.getNodeParameter('scanId', i) as number;
							const cancelType = this.getNodeParameter('cancelType', i) as string;
							const newDate = this.getNodeParameter('newDate', i, '') as string;
							endpoint = `/ds/${serverIpSecurityScan}/security-scan/${scanIdCancel}`;
							method = 'DELETE';
							body = {
								type: cancelType,
							};
							if (newDate) {
								body.new_date = newDate;
							}
							break;
					}
				}

				// Build URL with query parameters
				const url = new URL(apiUrl + endpoint);
				Object.keys(params).forEach((key) => {
					url.searchParams.append(key, params[key]);
				});

				// Prepare request options
				const requestOptions: any = {
					method: method,
					url: url.toString(),
					headers: {
						'Accept': format === 'json' ? 'application/json' : 'application/xml',
						'Content-Type': 'application/json',
					},
					json: format === 'json',
				};

				// Add body for PUT, POST request
				if (['PUT', 'POST'].includes(method) && body) {
					requestOptions.body = body;
				}

				// Make the API request
				const response = await this.helpers.httpRequest(requestOptions);

				returnData.push({
					json: typeof response === 'string' ? { data: response } : response,
					pairedItem: i,
				});
			} catch (error: any) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: error.message },
						pairedItem: i,
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}