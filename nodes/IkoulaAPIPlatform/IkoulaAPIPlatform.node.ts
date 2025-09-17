import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

import * as crypto from 'crypto';

export class IkoulaApiPlatform implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula API Platform',
		name: 'ikoulaApiPlatform',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula Platform API for platform management. Developed by Ascenzia - www.ascenzia.fr',
		defaults: {
			name: 'Ikoula API Platform',
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
						name: 'Platform',
						value: 'platform',
						description: 'Manage platforms',
					},
				],
				default: 'platform',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['platform'],
					},
				},
				options: [
					{
						name: 'Get Platform Dashboard',
						value: 'getPlatformDashboard',
						description: 'Get dashboard information for a platform',
						action: 'Get platform dashboard',
					},
					{
						name: 'Get Platform Details',
						value: 'getPlatformDetails',
						description: 'Get details of a specific platform',
						action: 'Get platform details',
					},
					{
						name: 'Get Platform Status',
						value: 'getPlatformStatus',
						description: 'Get status of a platform',
						action: 'Get platform status',
					},
					{
						name: 'Get Record Details',
						value: 'getRecordDetails',
						description: 'Get details of a specific record',
						action: 'Get record details',
					},
					{
						name: 'Get Server Items',
						value: 'getServerItems',
						description: 'Get items for a specific server in a platform',
						action: 'Get server items',
					},
					{
						name: 'List Platform Alerts',
						value: 'listPlatformAlerts',
						description: 'List alerts associated with a platform',
						action: 'List platform alerts',
					},
					{
						name: 'List Platform Interventions',
						value: 'listPlatformInterventions',
						description: 'List interventions for a platform',
						action: 'List platform interventions',
					},
					{
						name: 'List Platform Load Balancers',
						value: 'listPlatformLoadBalancers',
						description: 'List load balancers for a platform',
						action: 'List platform load balancers',
					},
					{
						name: 'List Platform Records',
						value: 'listPlatformRecords',
						description: 'List records (dossiers) for a platform',
						action: 'List platform records',
					},
					{
						name: 'List Platform Servers',
						value: 'listPlatformServers',
						description: 'List servers associated with a platform',
						action: 'List platform servers',
					},
					{
						name: 'List Platform Web Scenarios',
						value: 'listPlatformWebScenarios',
						description: 'List web scenarios for a platform',
						action: 'List platform web scenarios',
					},
					{
						name: 'List Platforms',
						value: 'listPlatforms',
						description: 'Lists all platforms',
						action: 'List all platforms',
					},
				],
				default: 'listPlatforms',
			},
			{
				displayName: 'Platform ID',
				name: 'platformId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['platform'],
						operation: [
							'getPlatformDetails',
							'getPlatformStatus',
							'getPlatformDashboard',
							'listPlatformServers',
							'listPlatformAlerts',
							'listPlatformWebScenarios',
							'listPlatformLoadBalancers',
							'listPlatformRecords',
							'getRecordDetails',
							'listPlatformInterventions',
							'getServerItems',
						],
					},
				},
				default: 0,
				description: 'The ID of the platform',
			},
			{
				displayName: 'Dossier ID',
				name: 'dossierId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['platform'],
						operation: ['getRecordDetails'],
					},
				},
				default: 0,
				description: 'The ID of the dossier/record',
			},
			{
				displayName: 'Server IP Address',
				name: 'serverIp',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['platform'],
						operation: ['getServerItems'],
					},
				},
				default: '',
				description: 'The IP address of the server',
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
				const operation = this.getNodeParameter('operation', i) as string;
				const format = this.getNodeParameter('format', i) as string;

				let endpoint = '';
				let method = 'GET';
				const params: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				// Determine the endpoint based on operation
				switch (operation) {
					case 'listPlatforms':
						endpoint = '/platform';
						method = 'GET';
						break;
					case 'getPlatformDetails':
						const platformIdDetails = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdDetails}`;
						method = 'GET';
						break;
					case 'getPlatformStatus':
						const platformIdStatus = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdStatus}/status`;
						method = 'GET';
						break;
					case 'getPlatformDashboard':
						const platformIdDashboard = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdDashboard}/dashboard`;
						method = 'GET';
						break;
					case 'listPlatformServers':
						const platformIdServers = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdServers}/servers`;
						method = 'GET';
						break;
					case 'listPlatformAlerts':
						const platformIdAlerts = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdAlerts}/alerts`;
						method = 'GET';
						break;
					case 'listPlatformWebScenarios':
						const platformIdWebScenarios = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdWebScenarios}/webscenarios`;
						method = 'GET';
						break;
					case 'listPlatformLoadBalancers':
						const platformIdLoadBalancers = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdLoadBalancers}/load-balancers`;
						method = 'GET';
						break;
					case 'listPlatformRecords':
						const platformIdRecords = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdRecords}/dossier`;
						method = 'GET';
						break;
					case 'getRecordDetails':
						const platformIdRecord = this.getNodeParameter('platformId', i) as number;
						const dossierId = this.getNodeParameter('dossierId', i) as number;
						endpoint = `/platform/${platformIdRecord}/dossier/${dossierId}`;
						method = 'GET';
						break;
					case 'listPlatformInterventions':
						const platformIdInterventions = this.getNodeParameter('platformId', i) as number;
						endpoint = `/platform/${platformIdInterventions}/interventions`;
						method = 'GET';
						break;
					case 'getServerItems':
						const platformIdServer = this.getNodeParameter('platformId', i) as number;
						const serverIp = this.getNodeParameter('serverIp', i) as string;
						endpoint = `/platform/${platformIdServer}/server/${serverIp}/items`;
						method = 'GET';
						break;
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