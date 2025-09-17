import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

export class IkoulaApiMicrosoft implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula API Microsoft',
		name: 'ikoulaApiMicrosoft',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula Microsoft API for Microsoft 365 account management',
		defaults: {
			name: 'Ikoula API Microsoft',
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
						name: 'Invoice',
						value: 'invoice',
						description: 'Manage Microsoft 365 invoices',
					},
					{
						name: 'Licence',
						value: 'licence',
						description: 'Manage Microsoft 365 licence',
					},
					{
						name: 'Microsoft',
						value: 'microsoft',
						description: 'Manage Microsoft 365 account',
					},
					{
						name: 'User',
						value: 'users',
						description: 'Manage Microsoft 365 users',
					},
				],
				default: 'microsoft',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['microsoft'],
					},
				},
				options: [
					{
						name: 'Force Synchronization',
						value: 'forceSynchronization',
						description: 'Force information update on Microsoft side',
						action: 'Force synchronization',
					},
					{
						name: 'Get Account Details',
						value: 'getAccountDetails',
						description: 'Get details of a specific Microsoft account',
						action: 'Get account details',
					},
					{
						name: 'List Accounts',
						value: 'listAccounts',
						description: 'List all Microsoft accounts',
						action: 'List all account',
					},
				],
				default: 'listAccounts',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['licence'],
					},
				},
				options: [
					{
						name: 'List Account Licences',
						value: 'listAccountLicences',
						description: 'List licences for an account',
						action: 'List account licence',
					},
					{
						name: 'List Orderable Licences',
						value: 'listOrderableLicences',
						description: 'List types of Microsoft licences that are orderable',
						action: 'List orderable licence',
					},
					{
						name: 'Order Licence',
						value: 'orderLicence',
						description: 'Order a new licence',
						action: 'Order licence',
					},
					{
						name: 'Terminate Licence',
						value: 'terminateLicence',
						description: 'Terminate a licence',
						action: 'Terminate licence',
					},
				],
				default: 'listAccountLicences',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['users'],
					},
				},
				options: [
					{
						name: 'Assign Licence to User',
						value: 'assignLicenceToUser',
						description: 'Assign one or more available licences to a specific user',
						action: 'Assign licence to user',
					},
					{
						name: 'Create User',
						value: 'createUser',
						description: 'Create a new user',
						action: 'Create user',
					},
					{
						name: 'Delete User',
						value: 'deleteUser',
						description: 'Delete the specified user',
						action: 'Delete user',
					},
					{
						name: 'Get Available Licences for User',
						value: 'getAvailableLicencesForUser',
						description: 'Lists the different licences that can be allocated to users',
						action: 'Get available licences for user',
					},
					{
						name: 'Get User Resources',
						value: 'getUserResources',
						description: 'Get mandatory resources for users creation and modification',
						action: 'Get user resources',
					},
					{
						name: 'List Users',
						value: 'listUsers',
						description: 'Lists the users linked to the Microsoft 365 account',
						action: 'List users',
					},
					{
						name: 'Reset User Password',
						value: 'resetUserPassword',
						description: 'Reset the temporary password of a user',
						action: 'Reset user password',
					},
					{
						name: 'Unassign Licence From User',
						value: 'unassignLicenceFromUser',
						description: 'Unassign a licence from a specific user',
						action: 'Unassign licence from user',
					},
					{
						name: 'Update User',
						value: 'updateUser',
						description: 'Update the user data',
						action: 'Update user',
					},
				],
				default: 'listUsers',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['invoice'],
					},
				},
				options: [
					{
						name: 'Get Invoice Details',
						value: 'getInvoiceDetails',
						description: 'Get details of a specific invoice',
						action: 'Get invoice details',
					},
					{
						name: 'List Invoices',
						value: 'listInvoices',
						description: 'Lists the account invoices',
						action: 'List invoices',
					},
				],
				default: 'listInvoices',
			},
			{
				displayName: 'Subscription ID',
				name: 'subscrId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['microsoft', 'licence', 'users', 'invoice'],
						operation: [
							'getAccountDetails',
							'forceSynchronization',
							'listAccountLicences',
							'listOrderableLicences',
							'orderLicence',
							'terminateLicence',
							'listUsers',
							'createUser',
							'updateUser',
							'deleteUser',
							'assignLicenceToUser',
							'unassignLicenceFromUser',
							'getAvailableLicencesForUser',
							'resetUserPassword',
							'getUserResources',
							'listInvoices',
							'getInvoiceDetails',
						],
					},
				},
				default: 0,
				description: 'The ID of the Microsoft subscription',
			},
			{
				displayName: 'Licence ID',
				name: 'licenceId',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['licence'],
						operation: ['terminateLicence'],
					},
				},
				default: '',
				description: 'The ID of the licence to terminate',
			},
			{
				displayName: 'Quantity',
				name: 'quantity',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['licence'],
						operation: ['terminateLicence'],
					},
				},
				default: 1,
				description: 'Number of licences to terminate',
			},
			{
				displayName: 'Licence Configuration',
				name: 'licenceConfig',
				type: 'fixedCollection',
				required: true,
				displayOptions: {
					show: {
						resource: ['licence'],
						operation: ['orderLicence'],
					},
				},
				default: {},
				placeholder: 'Add Licence',
				typeOptions: {
					multipleValues: true,
				},
				options: [
					{
						name: 'licenceValues',
						displayName: 'Licence',
						values: [
							{
								displayName: 'Licence Key',
								name: 'licenceKey',
								type: 'string',
								default: '',
								description: 'The licence key to order',
								required: true,
							},
							{
								displayName: 'Quantity',
								name: 'quantity',
								type: 'number',
								default: 1,
								description: 'Number of licences to order',
								required: true,
							},
							{
								displayName: 'Options',
								name: 'options',
								type: 'multiOptions',
								options: [
									{
										name: 'Assistance Option',
										value: 'option_assistance',
									},
									{
										name: 'Migration Option',
										value: 'option_migration',
									},
								],
								default: [],
								description: 'Additional options for the licence',
							},
						],
					},
				],
			},
			{
				displayName: 'User ID',
				name: 'userId',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['users'],
						operation: [
							'updateUser',
							'deleteUser',
							'assignLicenceToUser',
							'unassignLicenceFromUser',
							'getAvailableLicencesForUser',
							'resetUserPassword',
						],
					},
				},
				default: '',
				description: 'The ID of the user',
			},
			{
				displayName: 'User Data',
				name: 'userData',
				type: 'fixedCollection',
				required: true,
				displayOptions: {
					show: {
						resource: ['users'],
						operation: ['createUser', 'updateUser'],
					},
				},
				default: {},
				placeholder: 'Add User Data',
				options: [
					{
						name: 'userValues',
						displayName: 'User Information',
						values: [
							{
						displayName: 'Country',
						name: 'country',
						type: 'string',
						default: '',
						description: 'Country code for the user',
							required:	true,
							},
							{
						displayName: 'Display Name',
						name: 'displayName',
						type: 'string',
						default: '',
						description: 'Display name of the user',
							required:	true,
							},
							{
						displayName: 'Domain',
						name: 'domain',
						type: 'string',
						default: '',
						description: 'Domain for the user',
							required:	true,
							},
							{
						displayName: 'Email',
						name: 'email',
						type: 'string',
						placeholder: 'name@email.com',
						default: '',
						description: 'Email address of the user',
							required:	true,
							},
							{
						displayName: 'First Name',
						name: 'firstName',
						type: 'string',
						default: '',
						description: 'First name of the user',
							required:	true,
							},
							{
						displayName: 'Last Name',
						name: 'lastName',
						type: 'string',
						default: '',
						description: 'Last name of the user',
							required:	true,
							},
						],
					},
				],
			},
			{
				displayName: 'Licences to Assign',
				name: 'licencesToAssign',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['users'],
						operation: ['assignLicenceToUser'],
					},
				},
				default: '',
				description: 'Comma-separated list of licence IDs to assign to the user',
				placeholder: 'licence_id1,licence_id2',
			},
			{
				displayName: 'Licence ID to Unassign',
				name: 'licenceIdToUnassign',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['users'],
						operation: ['unassignLicenceFromUser'],
					},
				},
				default: '',
				description: 'The ID of the licence to unassign from the user',
			},
			{
				displayName: 'Invoice ID',
				name: 'invoiceId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['invoice'],
						operation: ['getInvoiceDetails'],
					},
				},
				default: 0,
				description: 'The ID of the invoice to get details for',
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
				const params: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				// Determine the endpoint and method based on operation
				switch (operation) {
					case 'listAccounts':
						endpoint = '/microsoft';
						method = 'GET';
						break;
					case 'getAccountDetails':
						const subscrIdDetails = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdDetails}`;
						method = 'GET';
						break;
					case 'forceSynchronization':
						const subscrIdSync = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdSync}/force-synchro`;
						method = 'GET';
						break;
					case 'listAccountLicences':
						const subscrIdLicences = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdLicences}/licence`;
						method = 'GET';
						break;
					case 'listOrderableLicences':
						const subscrIdOrderable = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdOrderable}/orderable-licence`;
						method = 'GET';
						break;
					case 'orderLicence':
						const subscrIdOrder = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdOrder}/licence`;
						method = 'POST';
						const licenceConfig = this.getNodeParameter('licenceConfig', i) as any;
						const licences = licenceConfig.licenceValues || [];
						params.LICENCE = licences.map((licence: any) => ({
							LICENCE_KEY: licence.licenceKey,
							QUANTITY: licence.quantity,
							OPTIONS: licence.options || [],
						}));
						break;
					case 'terminateLicence':
						const subscrIdTerminate = this.getNodeParameter('subscrId', i) as number;
						const licenceId = this.getNodeParameter('licenceId', i) as string;
						const quantity = this.getNodeParameter('quantity', i) as number;
						endpoint = `/microsoft/${subscrIdTerminate}/licence/${licenceId}`;
						method = 'DELETE';
						params.QUANTITY = quantity;
						break;
					case 'listUsers':
						const subscrIdUsers = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdUsers}/user`;
						method = 'GET';
						break;
					case 'createUser':
						const subscrIdCreate = this.getNodeParameter('subscrId', i) as number;
						const userDataCreate = this.getNodeParameter('userData', i) as any;
						const userData = userDataCreate.userValues || {};
						endpoint = `/microsoft/${subscrIdCreate}/user/create`;
						method = 'POST';
						params.FIRSTNAME = userData.firstName;
						params.LASTNAME = userData.lastName;
						params.DISPLAYNAME = userData.displayName;
						params.EMAIL = userData.email;
						params.DOMAIN = userData.domain;
						params.COUNTRY = userData.country;
						break;
					case 'updateUser':
						const subscrIdUpdate = this.getNodeParameter('subscrId', i) as number;
						const userIdUpdate = this.getNodeParameter('userId', i) as string;
						const userDataUpdate = this.getNodeParameter('userData', i) as any;
						const userDataUpd = userDataUpdate.userValues || {};
						endpoint = `/microsoft/${subscrIdUpdate}/user/${userIdUpdate}`;
						method = 'PUT';
						params.FIRSTNAME = userDataUpd.firstName;
						params.LASTNAME = userDataUpd.lastName;
						params.DISPLAYNAME = userDataUpd.displayName;
						params.EMAIL = userDataUpd.email;
						params.DOMAIN = userDataUpd.domain;
						params.COUNTRY = userDataUpd.country;
						break;
					case 'deleteUser':
						const subscrIdDelete = this.getNodeParameter('subscrId', i) as number;
						const userIdDelete = this.getNodeParameter('userId', i) as string;
						endpoint = `/microsoft/${subscrIdDelete}/user/${userIdDelete}`;
						method = 'DELETE';
						break;
					case 'assignLicenceToUser':
						const subscrIdAssign = this.getNodeParameter('subscrId', i) as number;
						const userIdAssign = this.getNodeParameter('userId', i) as string;
						const licencesToAssign = this.getNodeParameter('licencesToAssign', i) as string;
						endpoint = `/microsoft/${subscrIdAssign}/user/${userIdAssign}/licence-assign`;
						method = 'POST';
						params.LICENCES = licencesToAssign.split(',').map((id: string) => id.trim());
						break;
					case 'unassignLicenceFromUser':
						const subscrIdUnassign = this.getNodeParameter('subscrId', i) as number;
						const userIdUnassign = this.getNodeParameter('userId', i) as string;
						const licenceIdToUnassign = this.getNodeParameter('licenceIdToUnassign', i) as string;
						endpoint = `/microsoft/${subscrIdUnassign}/user/${userIdUnassign}/licence-unassign`;
						method = 'POST';
						params.LICENCE_ID = licenceIdToUnassign;
						break;
					case 'getAvailableLicencesForUser':
						const subscrIdAvailable = this.getNodeParameter('subscrId', i) as number;
						const userIdAvailable = this.getNodeParameter('userId', i) as string;
						endpoint = `/microsoft/${subscrIdAvailable}/user/${userIdAvailable}/get-licence-available`;
						method = 'GET';
						break;
					case 'resetUserPassword':
						const subscrIdReset = this.getNodeParameter('subscrId', i) as number;
						const userIdReset = this.getNodeParameter('userId', i) as string;
						endpoint = `/microsoft/${subscrIdReset}/user/${userIdReset}/password-reset`;
						method = 'GET';
						break;
					case 'getUserResources':
						const subscrIdResources = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdResources}/user/get-ressources`;
						method = 'GET';
						break;
					case 'listInvoices':
						const subscrIdInvoices = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/microsoft/${subscrIdInvoices}/invoice`;
						method = 'GET';
						break;
					case 'getInvoiceDetails':
						const subscrIdInvoiceDetails = this.getNodeParameter('subscrId', i) as number;
						const invoiceId = this.getNodeParameter('invoiceId', i) as number;
						endpoint = `/microsoft/${subscrIdInvoiceDetails}/invoice/${invoiceId}`;
						method = 'GET';
						break;
				}

				// Separate query parameters and body data
				const queryParams: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				const bodyData: any = {};

				// For POST, PUT and DELETE requests, separate body data from query params
				if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
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

				// Add body data for POST, PUT and DELETE requests
				if ((method === 'POST' || method === 'PUT' || method === 'DELETE') && Object.keys(bodyData).length > 0) {
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