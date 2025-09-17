import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

export class IkoulaBusinessApi implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula Business API',
		name: 'ikoulaBusinessApi',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula Business API for business operations management',
		defaults: {
			name: 'Ikoula Business API',
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
						name: 'Business',
						value: 'business',
						description: 'Manage business operations',
					},
				],
				default: 'business',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['business'],
					},
				},
				options: [
					{
						name: 'Cancel Termination',
						value: 'cancelTermination',
						description: 'Try to stop the termination of a specific account',
						action: 'Cancel termination',
					},
					{
						name: 'Get Categories',
						value: 'getCategories',
						description: 'Get all the products categories',
						action: 'Get categories',
					},
					{
						name: 'Get Category Products',
						value: 'getCategoryProducts',
						description: 'Lists the category products',
						action: 'Get category products',
					},
					{
						name: 'Get Invoice Details',
						value: 'getInvoiceDetails',

						action: 'Get invoice details',
					},
					{
						name: 'Get Payment Methods',
						value: 'getPaymentMethods',
						description: 'Get the payment method list',
						action: 'Get payment methods',
					},
					{
						name: 'Get Termination Info',
						value: 'getTerminationInfo',
						description: 'List of cancellable services and the list of reasons',
						action: 'Get termination info',
					},
					{
						name: 'Order Domain',
						value: 'orderDomain',
						description: 'Order a new domain',
						action: 'Order domain',
					},
					{
						name: 'Order Service',
						value: 'orderService',
						description: 'Order a new service',
						action: 'Order service',
					},
					{
						name: 'Terminate Account',
						value: 'terminateAccount',
						description: 'Termination of a specific account',
						action: 'Terminate account',
					},
				],
				default: 'getCategories',
			},
			{
				displayName: 'Category ID',
				name: 'categoryId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['business'],
						operation: ['getCategoryProducts'],
					},
				},
				default: 0,
				description: 'The ID of the product category',
			},
			{
				displayName: 'Invoice ID',
				name: 'invoiceId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['business'],
						operation: ['getInvoiceDetails'],
					},
				},
				default: 0,
				description: 'The ID of the invoice',
			},
			{
				displayName: 'Subscription ID',
				name: 'subscrId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['business'],
						operation: ['terminateAccount', 'cancelTermination'],
					},
				},
				default: 0,
				description: 'The ID of the subscription',
			},
			{
				displayName: 'Service Order Data',
				name: 'serviceOrderData',
				type: 'fixedCollection',
				required: true,
				displayOptions: {
					show: {
						resource: ['business'],
						operation: ['orderService'],
					},
				},
				default: {},
				placeholder: 'Add Service Order Data',
				options: [
					{
						name: 'serviceOrderValues',
						displayName: 'Service Order Information',
						values: [
							{
						displayName: 'Billing Cycle',
						name: 'facturationCycle',
						type: 'string',
						default: '',
						description: 'The billing cycle for the service',
							required:	true,
							},
							{
						displayName: 'Custom Options',
						name: 'customOptions',
						type: 'string',
						default: '',
						description: 'Custom options for the service',
							},
							{
						displayName: 'Domain',
						name: 'domain',
						type: 'string',
						default: '',
						description: 'Domain associated with the service',
							},
							{
						displayName: 'Payment Method ID',
						name: 'paymentMethodId',
						type: 'number',
						default: 0,
						description: 'The ID of the payment method',
							required:	true,
							},
							{
						displayName: 'Product ID',
						name: 'productId',
						type: 'number',
						default: 0,
						description: 'The ID of the product to order',
							required:	true,
							},
							{
						displayName: 'Promotional Code',
						name: 'promotionalCode',
						type: 'string',
						default: '',
						description: 'Promotional code to apply',
							},
						],
					},
				],
			},
			{
				displayName: 'Domain Order Data',
				name: 'domainOrderData',
				type: 'fixedCollection',
				required: true,
				displayOptions: {
					show: {
						resource: ['business'],
						operation: ['orderDomain'],
					},
				},
				default: {},
				placeholder: 'Add Domain Order Data',
				options: [
					{
						name: 'domainOrderValues',
						displayName: 'Domain Order Information',
						values: [
							{
						displayName: 'Action',
						name: 'action',
						type: 'string',
						default: '',
							required:	true,
							},
							{
						displayName: 'Billing Cycle',
						name: 'facturationCycle',
						type: 'string',
						default: '',
						description: 'The billing cycle for the domain',
							required:	true,
							},
							{
						displayName: 'Domain',
						name: 'domain',
						type: 'string',
						default: '',
						description: 'The domain name to order',
							required:	true,
							},
							{
						displayName: 'EPP Code',
						name: 'eppCode',
						type: 'string',
						default: '',
						description: 'EPP code for domain transfer',
							},
							{
						displayName: 'Payment Method ID',
						name: 'paymentMethodId',
						type: 'string',
						default: '',
						description: 'The ID of the payment method',
							required:	true,
							},
							{
						displayName: 'Promotional Code',
						name: 'promotionalCode',
						type: 'string',
						default: '',
						description: 'Promotional code to apply',
							},
							{
						displayName: 'TLD ID',
						name: 'tldId',
						type: 'string',
						default: '',
						description: 'The ID of the top-level domain',
							required:	true,
							},
						],
					},
				],
			},
			{
				displayName: 'Termination Data',
				name: 'terminationData',
				type: 'fixedCollection',
				required: true,
				displayOptions: {
					show: {
						resource: ['business'],
						operation: ['terminateAccount'],
					},
				},
				default: {},
				placeholder: 'Add Termination Data',
				options: [
					{
						name: 'terminationValues',
						displayName: 'Termination Information',
						values: [
							{
								displayName: 'Type',
								name: 'type',
								type: 'options',
								options: [
									{
										name: 'End of Period',
										value: 1,
										description: 'Termination of the service at the end of the period',
									},
									{
										name: 'Immediate',
										value: 2,
										description: 'Immediate cancellation of the service',
									},
								],
								default: 1,
								description: 'Type of termination',
								required: true,
							},
							{
								displayName: 'Reason ID',
								name: 'reason',
								type: 'number',
								default: 0,
								description: 'Reason ID for termination (get IDs from termination info)',
								required: true,
							},
							{
								displayName: 'Description',
								name: 'description',
								type: 'string',
								default: '',
								description: 'Description (mandatory for "Other" reason with ID -1)',
							},
						],
					},
				],
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
					case 'getCategories':
						endpoint = '/business/category';
						method = 'GET';
						break;
					case 'getCategoryProducts':
						const categoryId = this.getNodeParameter('categoryId', i) as number;
						endpoint = `/business/category/${categoryId}/products`;
						method = 'GET';
						break;
					case 'getPaymentMethods':
						endpoint = '/business/payment-method';
						method = 'GET';
						break;
					case 'getInvoiceDetails':
						const invoiceId = this.getNodeParameter('invoiceId', i) as number;
						endpoint = `/business/invoice/${invoiceId}`;
						method = 'GET';
						break;
					case 'getTerminationInfo':
						endpoint = '/business/resiliation';
						method = 'GET';
						break;
					case 'cancelTermination':
						const subscrIdCancel = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/business/resiliation/${subscrIdCancel}/cancel`;
						method = 'GET';
						break;
					case 'orderService':
						endpoint = '/business/order/service';
						method = 'POST';
						const serviceOrderData = this.getNodeParameter('serviceOrderData', i) as any;
						const serviceData = serviceOrderData.serviceOrderValues || {};
						params.product_id = serviceData.productId;
						params.payment_method_id = serviceData.paymentMethodId;
						params.facturation_cycle = serviceData.facturationCycle;
						if (serviceData.customOptions) params.custom_options = serviceData.customOptions;
						if (serviceData.domain) params.domain = serviceData.domain;
						if (serviceData.promotionalCode) params.promotional_code = serviceData.promotionalCode;
						break;
					case 'orderDomain':
						endpoint = '/business/order/domain';
						method = 'POST';
						const domainOrderData = this.getNodeParameter('domainOrderData', i) as any;
						const domainData = domainOrderData.domainOrderValues || {};
						params.domain = domainData.domain;
						params.tld_id = domainData.tldId;
						params.payment_method_id = domainData.paymentMethodId;
						params.facturation_cycle = domainData.facturationCycle;
						params.action = domainData.action;
						if (domainData.eppCode) params.epp_code = domainData.eppCode;
						if (domainData.promotionalCode) params.promotional_code = domainData.promotionalCode;
						break;
					case 'terminateAccount':
						const subscrIdTerminate = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/business/resiliation/${subscrIdTerminate}`;
						method = 'POST';
						const terminationData = this.getNodeParameter('terminationData', i) as any;
						const termData = terminationData.terminationValues || {};
						params.type = termData.type;
						params.reason = termData.reason;
						if (termData.description) params.description = termData.description;
						break;
				}

				// Separate query parameters and body data
				const queryParams: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				const bodyData: any = {};

				// For POST requests, separate body data from query params
				if (method === 'POST') {
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

				// Add body data for POST requests
				if (method === 'POST' && Object.keys(bodyData).length > 0) {
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