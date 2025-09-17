import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

export class IkoulaApiikic implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula API IKIC',
		name: 'ikoulaApiikic',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula IKIC API for account management',
		defaults: {
			name: 'Ikoula API IKIC',
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
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'List IKIC Accounts',
						value: 'listAccounts',
						description: 'Lists all IKIC accounts',
						action: 'Lists all IKIC accounts',
					},
					{
						name: 'Get Account Statistics',
						value: 'getAccountStats',
						description: 'Get statistics for a specific account',
						action: 'Get statistics for a specific account',
					},
					{
						name: 'Modify Password',
						value: 'modifyPassword',
						description: 'Modifies the IKIC password for an account',
						action: 'Modifies the IKIC password for an account',
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
						operation: ['getAccountStats', 'modifyPassword'],
					},
				},
				default: 0,

			},
			{
				displayName: 'Period',
				name: 'period',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['getAccountStats'],
					},
				},
				default: '',
				description: 'The period for statistics (optional)',
			},
			{
				displayName: 'New IKIC Password',
				name: 'passwordIkic',
				type: 'string',
				typeOptions: {
					password: true,
				},
				required: true,
				displayOptions: {
					show: {
						operation: ['modifyPassword'],
					},
				},
				default: '',

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
		const publicKeyPath = path.join(__dirname, '../../../Ikoula.API.RSAKeyPub.pem');
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

				// Determine the endpoint and method based on operation
				switch (operation) {
					case 'listAccounts':
						endpoint = '/ikic';
						method = 'GET';
						break;
					case 'getAccountStats':
						const subscrId = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/ikic/${subscrId}`;
						method = 'GET';
						const period = this.getNodeParameter('period', i, '') as string;
						if (period) {
							params.period = period;
						}
						break;
					case 'modifyPassword':
						const subscrIdModify = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/ikic/${subscrIdModify}`;
						method = 'PUT';
						const passwordIkic = this.getNodeParameter('passwordIkic', i) as string;
						body = {
							password_ikic: passwordIkic,
						};
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

				// Add body for PUT request
				if (method === 'PUT' && body) {
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