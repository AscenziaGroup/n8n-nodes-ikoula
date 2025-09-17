import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

import * as crypto from 'crypto';

export class IkoulaApiEset implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula API ESET',
		name: 'ikoulaApiEset',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula ESET API for ESET antivirus services management. Developed by Ascenzia - www.ascenzia.fr',
		defaults: {
			name: 'Ikoula API ESET',
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
						name: 'Eset',
						value: 'eset',
						description: 'Manage ESET antivirus service',
					},
				],
				default: 'eset',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['eset'],
					},
				},
				options: [
					{
						name: 'Get Account Details',
						value: 'getAccountDetails',
						description: 'Get details of a specific ESET account',
						action: 'Get account details',
					},
					{
						name: 'List Accounts',
						value: 'listAccounts',
						description: 'List all ESET accounts',
						action: 'List all accounts',
					},
				],
				default: 'listAccounts',
			},
			{
				displayName: 'Subscription ID',
				name: 'subscrId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['eset'],
						operation: ['getAccountDetails'],
					},
				},
				default: 0,
				description: 'The ID of the ESET service subscription',
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
					case 'listAccounts':
						endpoint = '/eset';
						method = 'GET';
						break;
					case 'getAccountDetails':
						const subscrId = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/eset/${subscrId}`;
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