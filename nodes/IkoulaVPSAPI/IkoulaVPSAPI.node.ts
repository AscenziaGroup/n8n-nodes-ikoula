import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

export class IkoulaVpsapi implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula VPS API',
		name: 'ikoulaVpsapi',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["resource"] + ": " + $parameter["operation"]}}',
		description: 'Interact with Ikoula VPS API',
		defaults: {
			name: 'Ikoula VPS API',
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
						name: 'VPS DNS Secondary',
						value: 'vpsDnsSecondary',
						description: 'Manage secondary DNS',
					},
					{
						name: 'VPS Reset',
						value: 'vpsReset',
						description: 'Reset virtual machine with new OS',
					},
					{
						name: 'VPS Reverse DN',
						value: 'vpsReverseDns',
						description: 'Manage reverse DNS',
					},
					{
						name: 'VPS Security Scan',
						value: 'vpsSecurityScan',
						description: 'Manage security scans',
					},
					{
						name: 'VPS Snapshot',
						value: 'vpsSnapshot',
						description: 'Manage VPS snapshots',
					},
					{
						name: 'VPS Summary',
						value: 'vpsSummary',
						description: 'Main VPS operations and information',
					},
				],
				default: 'vpsSummary',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vpsSummary'],
					},
				},
				options: [
					{
						name: 'Get Service Details',
						value: 'getServiceDetails',
						description: 'Get detailed information about a specific VPS service',
						action: 'Get service details a vps summary',
					},
					{
						name: 'Get Status',
						value: 'getStatus',
						description: 'Get the status of the virtual machine',
						action: 'Get status a vps summary',
					},
					{
						name: 'List Services',
						value: 'listServices',
						description: 'Lists all VPS client services',
						action: 'List services a vps summary',
					},
					{
						name: 'Pause',
						value: 'pause',
						description: 'Pause the virtual machine',
						action: 'Pause a vps summary',
					},
					{
						name: 'Resume',
						value: 'resume',
						description: 'Resume the virtual machine',
						action: 'Resume a vps summary',
					},
					{
						name: 'Shutdown (Software)',
						value: 'shutdown',
						description: 'Stop the virtual machine (Software)',
						action: 'Shutdown software a vps summary',
					},
					{
						name: 'Start',
						value: 'start',
						description: 'Start the virtual machine',
						action: 'Start a vps summary',
					},
					{
						name: 'Stop (Hardware)',
						value: 'stop',
						description: 'Stop the virtual machine (Hardware)',
						action: 'Stop hardware a vps summary',
					},
					{
						name: 'Suspend',
						value: 'suspend',
						description: 'Suspend the virtual machine',
						action: 'Suspend a vps summary',
					},
				],
				default: 'listServices',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vpsSnapshot'],
					},
				},
				options: [
					{
						name: 'List Snapshots',
						value: 'listSnapshots',
						description: 'List all snapshots of the virtual machine',
						action: 'List snapshots a vps snapshot',
					},
					{
						name: 'Create Snapshot',
						value: 'createSnapshot',
						description: 'Create a new snapshot of the virtual machine',
						action: 'Create snapshot a vps snapshot',
					},
					{
						name: 'Rollback to Snapshot',
						value: 'rollbackSnapshot',
						description: 'Rollback the virtual machine to a specific snapshot',
						action: 'Rollback to snapshot a vps snapshot',
					},
					{
						name: 'Delete Snapshot',
						value: 'deleteSnapshot',
						description: 'Delete a specific snapshot',
						action: 'Delete snapshot a vps snapshot',
					},
				],
				default: 'listSnapshots',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vpsDnsSecondary'],
					},
				},
				options: [
					{
						name: 'List Secondary DNS',
						value: 'listDnsSecondary',
						description: 'List all secondary DNS entries',
						action: 'List secondary dns a vps dns secondary',
					},
					{
						name: 'Add Secondary DNS',
						value: 'addDnsSecondary',
						description: 'Add a new secondary DNS entry',
						action: 'Add secondary dns a vps dns secondary',
					},
					{
						name: 'Modify Secondary DNS',
						value: 'modifyDnsSecondary',
						description: 'Modify an existing secondary DNS entry',
						action: 'Modify secondary dns a vps dns secondary',
					},
					{
						name: 'Delete Secondary DNS',
						value: 'deleteDnsSecondary',
						description: 'Delete a secondary DNS entry',
						action: 'Delete secondary dns a vps dns secondary',
					},
				],
				default: 'listDnsSecondary',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vpsReverseDns'],
					},
				},
				options: [
					{
						name: 'List Reverse DNS',
						value: 'listReverseDns',
						description: 'List all reverse DNS entries',
						action: 'List reverse dns a vps reverse dns',
					},
					{
						name: 'Modify Reverse DNS',
						value: 'modifyReverseDns',
						description: 'Modify a reverse DNS entry',
						action: 'Modify reverse dns a vps reverse dns',
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
						resource: ['vpsSecurityScan'],
					},
				},
				options: [
					{
						name: 'List Security Scans',
						value: 'listSecurityScans',
						description: 'List all security scans',
						action: 'List security scans a vps security scan',
					},
					{
						name: 'Request Security Scan',
						value: 'requestSecurityScan',
						description: 'Request a new security scan',
						action: 'Request security scan a vps security scan',
					},
					{
						name: 'Get Scan Results',
						value: 'getScanResults',
						description: 'Get the results of a security scan',
						action: 'Get scan results a vps security scan',
					},
					{
						name: 'Stop Security Scan',
						value: 'stopSecurityScan',
						description: 'Stop a running security scan',
						action: 'Stop security scan a vps security scan',
					},
				],
				default: 'listSecurityScans',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vpsReset'],
					},
				},
				options: [
					{
						name: 'List Available OS',
						value: 'listAvailableOS',
						description: 'List all available operating systems for reset',
						action: 'List available os a vps reset',
					},
					{
						name: 'Reset Virtual Machine',
						value: 'resetVM',
						description: 'Reset the virtual machine with a new OS',
						action: 'Reset virtual machine a vps reset',
					},
				],
				default: 'listAvailableOS',
			},
			{
				displayName: 'Subscription ID',
				name: 'subscrId',
				type: 'number',
				required: true,
				displayOptions: {
					hide: {
						resource: ['vpsSummary'],
						operation: ['listServices'],
					},
				},
				default: 0,
				description: 'The VPS subscription ID',
			},
			{
				displayName: 'Snapshot Name',
				name: 'snapshotName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsSnapshot'],
						operation: ['rollbackSnapshot', 'deleteSnapshot'],
					},
				},
				default: '',
				description: 'The name of the snapshot',
			},
			{
				displayName: 'Server IP',
				name: 'serverIp',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsDnsSecondary', 'vpsReverseDns', 'vpsSecurityScan'],
					},
				},
				default: '',
				description: 'The server IP address',
			},
			{
				displayName: 'DNS Name',
				name: 'dnsName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsDnsSecondary'],
						operation: ['addDnsSecondary', 'modifyDnsSecondary'],
					},
				},
				default: '',
				description: 'The DNS name to add or modify',
			},
			{
				displayName: 'DNS ID',
				name: 'dnsId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsDnsSecondary'],
						operation: ['modifyDnsSecondary', 'deleteDnsSecondary'],
					},
				},
				default: 0,
				description: 'The DNS entry ID',
			},
			{
				displayName: 'Reverse DNS ID',
				name: 'reverseDnsId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsReverseDns'],
						operation: ['modifyReverseDns'],
					},
				},
				default: 0,
				description: 'The reverse DNS entry ID',
			},
			{
				displayName: 'Reverse DNS Name',
				name: 'reverseDnsName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsReverseDns'],
						operation: ['modifyReverseDns'],
					},
				},
				default: '',
				description: 'The reverse DNS name to set',
			},
			{
				displayName: 'Scan Date',
				name: 'scanDate',
				type: 'string',

				displayOptions: {
					show: {
						resource: ['vpsSecurityScan'],
						operation: ['requestSecurityScan'],
					},
				},
				default: '',
				description: 'The date to schedule the scan (optional)',
			},
			{
				displayName: 'Scan ID',
				name: 'scanId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsSecurityScan'],
						operation: ['getScanResults', 'stopSecurityScan'],
					},
				},
				default: 0,
				description: 'The security scan ID',
			},
			{
				displayName: 'Operating System ID',
				name: 'osId',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['vpsReset'],
						operation: ['resetVM'],
					},
				},
				default: '',
				description: 'The ID of the operating system to install',
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

		// Dynamic imports for Node.js modules
		const fs = await import('fs');
		const path = await import('path');
		const crypto = await import('crypto');

		// Get public key for encryption
		const publicKeyPath = path.join(process.cwd(), 'Ikoula.API.RSAKeyPub.pem');
		let publicKey: string;

		try {
			publicKey = fs.readFileSync(publicKeyPath, 'utf8');
		} catch (error: any) {
			throw new NodeOperationError(
				this.getNode(),
				`Failed to read public key file: ${error.message}`,
			);
		}

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
				const params: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				// Determine the endpoint and method based on resource and operation
				if (resource === 'vpsSummary') {
					switch (operation) {
						case 'listServices':
							endpoint = '/vps';
							method = 'GET';
							break;
						case 'getServiceDetails':
							const subscrId = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrId}`;
							method = 'GET';
							break;
						case 'getStatus':
							const subscrIdStatus = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdStatus}/status`;
							method = 'GET';
							break;
						case 'start':
							const subscrIdStart = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdStart}/start`;
							method = 'PUT';
							break;
						case 'stop':
							const subscrIdStop = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdStop}/stop`;
							method = 'PUT';
							break;
						case 'shutdown':
							const subscrIdShutdown = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdShutdown}/shutdown`;
							method = 'PUT';
							break;
						case 'pause':
							const subscrIdPause = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdPause}/pause`;
							method = 'PUT';
							break;
						case 'resume':
							const subscrIdResume = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdResume}/resume`;
							method = 'PUT';
							break;
						case 'suspend':
							const subscrIdSuspend = this.getNodeParameter('subscrId', i) as number;
							endpoint = `/vps/${subscrIdSuspend}/suspend`;
							method = 'PUT';
							break;
					}
				} else if (resource === 'vpsSnapshot') {
					const subscrId = this.getNodeParameter('subscrId', i) as number;
					switch (operation) {
						case 'listSnapshots':
							endpoint = `/vps/${subscrId}/snapshot`;
							method = 'GET';
							break;
						case 'createSnapshot':
							endpoint = `/vps/${subscrId}/snapshot`;
							method = 'POST';
							break;
						case 'rollbackSnapshot':
							const snapshotNameRollback = this.getNodeParameter('snapshotName', i) as string;
							endpoint = `/vps/${subscrId}/snapshot/${snapshotNameRollback}`;
							method = 'POST';
							break;
						case 'deleteSnapshot':
							const snapshotNameDelete = this.getNodeParameter('snapshotName', i) as string;
							endpoint = `/vps/${subscrId}/snapshot/${snapshotNameDelete}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'vpsDnsSecondary') {
					const serverIp = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listDnsSecondary':
							endpoint = `/vps/${serverIp}/dns-sec`;
							method = 'GET';
							break;
						case 'addDnsSecondary':
							endpoint = `/vps/${serverIp}/dns-sec`;
							method = 'POST';
							break;
						case 'modifyDnsSecondary':
							const dnsIdModify = this.getNodeParameter('dnsId', i) as number;
							endpoint = `/vps/${serverIp}/dns-sec/${dnsIdModify}`;
							method = 'PUT';
							break;
						case 'deleteDnsSecondary':
							const dnsIdDelete = this.getNodeParameter('dnsId', i) as number;
							endpoint = `/vps/${serverIp}/dns-sec/${dnsIdDelete}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'vpsReverseDns') {
					const serverIp = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listReverseDns':
							endpoint = `/vps/${serverIp}/reverse-dns`;
							method = 'GET';
							break;
						case 'modifyReverseDns':
							const reverseDnsId = this.getNodeParameter('reverseDnsId', i) as number;
							endpoint = `/vps/${serverIp}/reverse-dns/${reverseDnsId}`;
							method = 'PUT';
							break;
					}
				} else if (resource === 'vpsSecurityScan') {
					const serverIp = this.getNodeParameter('serverIp', i) as string;

					switch (operation) {
						case 'listSecurityScans':
							endpoint = `/vps/${serverIp}/scan-secu`;
							method = 'GET';
							break;
						case 'requestSecurityScan':
							endpoint = `/vps/${serverIp}/scan-secu`;
							method = 'POST';
							break;
						case 'getScanResults':
							const scanIdGet = this.getNodeParameter('scanId', i) as number;
							endpoint = `/vps/${serverIp}/scan-secu/${scanIdGet}`;
							method = 'GET';
							break;
						case 'stopSecurityScan':
							const scanIdStop = this.getNodeParameter('scanId', i) as number;
							endpoint = `/vps/${serverIp}/scan-secu/${scanIdStop}`;
							method = 'DELETE';
							break;
					}
				} else if (resource === 'vpsReset') {
					const subscrId = this.getNodeParameter('subscrId', i) as number;

					switch (operation) {
						case 'listAvailableOS':
							endpoint = `/vps/${subscrId}/raz`;
							method = 'GET';
							break;
						case 'resetVM':
							endpoint = `/vps/${subscrId}/raz`;
							method = 'POST';
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

				// Add body for POST/PUT requests for DNS Secondary
				if (resource === 'vpsDnsSecondary' && ['POST', 'PUT'].includes(method) &&
					['addDnsSecondary', 'modifyDnsSecondary'].includes(operation)) {
					const dnsName = this.getNodeParameter('dnsName', i) as string;
					requestOptions.body = {
						dns_name: dnsName,
					};
				}

				// Add body for PUT request for Reverse DNS (form-urlencoded)
				if (resource === 'vpsReverseDns' && method === 'PUT' && operation === 'modifyReverseDns') {
					const reverseDnsName = this.getNodeParameter('reverseDnsName', i) as string;
					// For form-urlencoded, we need to send as query params in the body
					requestOptions.headers['Content-Type'] = 'application/x-www-form-urlencoded';
					requestOptions.body = `reverse_dns_name=${encodeURIComponent(reverseDnsName)}`;
					requestOptions.json = false;
				}

				// Add body for POST request for Security Scan
				if (resource === 'vpsSecurityScan' && method === 'POST' && operation === 'requestSecurityScan') {
					const scanDate = this.getNodeParameter('scanDate', i, '') as string;
					if (scanDate) {
						requestOptions.body = {
							scan_date: scanDate,
						};
					}
				}

				// Add body for POST request for VPS Reset
				if (resource === 'vpsReset' && method === 'POST' && operation === 'resetVM') {
					const osId = this.getNodeParameter('osId', i) as string;
					requestOptions.body = {
						os_id: osId,
					};
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