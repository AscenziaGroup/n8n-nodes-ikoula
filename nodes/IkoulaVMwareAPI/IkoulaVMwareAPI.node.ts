import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

export class IkoulaVMwareAPI implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula VMware API',
		name: 'ikoulaVmwareApi',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula VMware API for VMware services management',
		defaults: {
			name: 'Ikoula VMware API',
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
						name: 'VMware',
						value: 'vmware',
						description: 'Manage VMware service',
					},
				],
				default: 'vmware',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['vmware'],
					},
				},
				options: [
					{
						name: 'Get Account Details',
						value: 'getAccountDetails',
						description: 'Get details of a specific VMware account',
						action: 'Get account details',
					},
					{
						name: 'List Accounts',
						value: 'listAccounts',
						description: 'List all VMware accounts',
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
						resource: ['vmware'],
						operation: ['getAccountDetails'],
					},
				},
				default: 0,
				description: 'The ID of the VMware service subscription',
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
						endpoint = '/vmware';
						method = 'GET';
						break;
					case 'getAccountDetails':
						const subscrId = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/vmware/${subscrId}`;
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