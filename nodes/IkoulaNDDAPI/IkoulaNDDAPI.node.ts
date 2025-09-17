import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

export class IkoulaNDDAPI implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula NDD API',
		name: 'ikoulaNddApi',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula NDD API for domain name services and DNS management',
		defaults: {
			name: 'Ikoula NDD API',
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
						name: 'NDD',
						value: 'ndd',
						description: 'Manage domain name service',
					},
				],
				default: 'ndd',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['ndd'],
					},
				},
				options: [
					{
						name: 'Add DNS Registration',
						value: 'addDnsRegistration',
						description: 'Add a DNS registration for certbot',
						action: 'Add DNS registration',
					},
					{
						name: 'Delete DNS Registration',
						value: 'deleteDnsRegistration',
						description: 'Delete a DNS registration for certbot',
						action: 'Delete DNS registration',
					},
					{
						name: 'Get Account Details',
						value: 'getAccountDetails',
						description: 'Get details of a specific NDD account',
						action: 'Get account details',
					},
					{
						name: 'List Accounts',
						value: 'listAccounts',
						description: 'Get NDD accounts list',
						action: 'List accounts',
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
						resource: ['ndd'],
						operation: ['getAccountDetails'],
					},
				},
				default: 0,
				description: 'The ID of the NDD service subscription',
			},
			{
				displayName: 'Certbot Domain',
				name: 'certbotDomain',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['ndd'],
						operation: ['addDnsRegistration', 'deleteDnsRegistration'],
					},
				},
				default: '',
				description: 'The domain name for certbot DNS registration',
			},
			{
				displayName: 'Certbot Validation',
				name: 'certbotValidation',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['ndd'],
						operation: ['addDnsRegistration', 'deleteDnsRegistration'],
					},
				},
				default: '',
				description: 'The validation string for certbot DNS registration',
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

				// Determine the endpoint and method based on operation
				switch (operation) {
					case 'listAccounts':
						endpoint = '/ndd';
						method = 'GET';
						break;
					case 'getAccountDetails':
						const subscrId = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/ndd/${subscrId}`;
						method = 'GET';
						break;
					case 'addDnsRegistration':
						endpoint = '/ndd/certbot-dns';
						method = 'POST';
						const certbotDomainAdd = this.getNodeParameter('certbotDomain', i) as string;
						const certbotValidationAdd = this.getNodeParameter('certbotValidation', i) as string;
						params.certbot_domain = certbotDomainAdd;
						params.certbot_validation = certbotValidationAdd;
						break;
					case 'deleteDnsRegistration':
						const certbotDomainDelete = this.getNodeParameter('certbotDomain', i) as string;
						const certbotValidationDelete = this.getNodeParameter('certbotValidation', i) as string;
						endpoint = `/ndd/certbot-dns/${certbotDomainDelete}`;
						method = 'DELETE';
						params.certbot_validation = certbotValidationDelete;
						break;
				}

				// Separate query parameters and body data
				const queryParams: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				const bodyData: any = {};

				// For POST and DELETE requests, separate body data from query params
				if (method === 'POST' || method === 'DELETE') {
					Object.keys(params).forEach((key) => {
						if (['login', 'crypted_password', 'format'].includes(key)) {
							queryParams[key] = params[key];
						} else {
							bodyData[key] = params[key];
						}
					});
				} else {
					// For GET requests, all params go to query string
					Object.assign(queryParams, params);
				}

				// Build URL with query parameters
				const url = new URL(apiUrl + endpoint);
				Object.keys(queryParams).forEach((key) => {
					url.searchParams.append(key, queryParams[key]);
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

				// Add body data for POST and DELETE requests
				if ((method === 'POST' || method === 'DELETE') && Object.keys(bodyData).length > 0) {
					if (format === 'json') {
						requestOptions.body = bodyData;
					} else {
						requestOptions.form = bodyData;
					}
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