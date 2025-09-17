import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

import * as crypto from 'crypto';

export class IkoulaApiVeeam implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Ikoula API Veeam',
		name: 'ikoulaApiVeeam',
		icon: 'file:logo_IKOULA_light_fr.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Ikoula Veeam API for backup management',
		defaults: {
			name: 'Ikoula API Veeam',
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
						name: 'Backup',
						value: 'backup',
						description: 'Manage Veeam backup operations',
					},
					{
						name: 'Backup Policy',
						value: 'backupPolicy',
						description: 'Manage Veeam backup policies',
					},
					{
						name: 'Management',
						value: 'management',
						description: 'Manage Veeam management agents',
					},
					{
						name: 'Veeam',
						value: 'veeam',
						description: 'Manage Veeam backup accounts',
					},
				],
				default: 'veeam',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['veeam'],
					},
				},
				options: [
					{
						name: 'Assign Backup Policy',
						value: 'assignBackupPolicy',
						description: 'Assign a backup policy to a backup agent',
						action: 'Assign backup policy',
					},
					{
						name: 'Create Backup Policy',
						value: 'createBackupPolicy',
						description: 'Create a new backup policy',
						action: 'Create backup policy',
					},
					{
						name: 'Delete Backup Job',
						value: 'deleteBackupJob',
						description: 'Delete a backup job',
						action: 'Delete backup job',
					},
					{
						name: 'Delete Backup Policy',
						value: 'deleteBackupPolicy',
						description: 'Delete a backup policy',
						action: 'Delete backup policy',
					},
					{
						name: 'Delete Management Agent',
						value: 'deleteManagementAgent',
						description: 'Delete a management agent',
						action: 'Delete management agent',
					},
					{
						name: 'Get Veeam Account Details',
						value: 'getVeeamAccountDetails',
						description: 'Get details of a specific Veeam account',
						action: 'Get veeam account details',
					},
					{
						name: 'Install Backup Agent',
						value: 'installBackupAgent',
						description: 'Install a backup agent through management agent',
						action: 'Install backup agent',
					},
					{
						name: 'List Backup Policies',
						value: 'listBackupPolicies',
						description: 'List all backup policies for an account',
						action: 'List backup policies',
					},
					{
						name: 'List Veeam Accounts',
						value: 'listVeeamAccounts',
						description: 'List all Veeam accounts',
						action: 'List veeam accounts',
					},
					{
						name: 'List Veeam Agents',
						value: 'listVeeamAgents',
						description: 'List agents of a Veeam account',
						action: 'List veeam agents',
					},
					{
						name: 'Restart Backup Agent',
						value: 'restartBackupAgent',
						description: 'Restart a backup agent',
						action: 'Restart backup agent',
					},
					{
						name: 'Restart Management Agent',
						value: 'restartManagementAgent',
						description: 'Restart a management agent',
						action: 'Restart management agent',
					},
					{
						name: 'Start Backup Job',
						value: 'startBackupJob',
						description: 'Start a backup job',
						action: 'Start backup job',
					},
					{
						name: 'Stop Backup Job',
						value: 'stopBackupJob',
						description: 'Stop a backup job',
						action: 'Stop backup job',
					},
				],
				default: 'listVeeamAccounts',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['backup'],
					},
				},
				options: [
					{
						name: 'Assign Backup Policy',
						value: 'assignBackupPolicy',
						description: 'Assign a backup policy to a backup agent',
						action: 'Assign backup policy',
					},
					{
						name: 'Delete Backup Job',
						value: 'deleteBackupJob',
						description: 'Delete a backup job',
						action: 'Delete backup job',
					},
					{
						name: 'Restart Backup Agent',
						value: 'restartBackupAgent',
						description: 'Restart a backup agent',
						action: 'Restart backup agent',
					},
					{
						name: 'Start Backup Job',
						value: 'startBackupJob',
						description: 'Start a backup job',
						action: 'Start backup job',
					},
					{
						name: 'Stop Backup Job',
						value: 'stopBackupJob',
						description: 'Stop a backup job',
						action: 'Stop backup job',
					},
				],
				default: 'startBackupJob',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['management'],
					},
				},
				options: [
					{
						name: 'Delete Management Agent',
						value: 'deleteManagementAgent',
						description: 'Delete a management agent',
						action: 'Delete management agent',
					},
					{
						name: 'Install Backup Agent',
						value: 'installBackupAgent',
						description: 'Install a backup agent through management agent',
						action: 'Install backup agent',
					},
					{
						name: 'Restart Management Agent',
						value: 'restartManagementAgent',
						description: 'Restart a management agent',
						action: 'Restart management agent',
					},
				],
				default: 'restartManagementAgent',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['backupPolicy'],
					},
				},
				options: [
					{
						name: 'Assign Backup Policy',
						value: 'assignBackupPolicy',
						description: 'Assign a backup policy to a backup agent',
						action: 'Assign backup policy',
					},
					{
						name: 'Create Backup Policy',
						value: 'createBackupPolicy',
						description: 'Create a new backup policy',
						action: 'Create backup policy',
					},
					{
						name: 'Delete Backup Policy',
						value: 'deleteBackupPolicy',
						description: 'Delete a backup policy',
						action: 'Delete backup policy',
					},
					{
						name: 'List Backup Policies',
						value: 'listBackupPolicies',
						description: 'List all backup policies for an account',
						action: 'List backup policies',
					},
				],
				default: 'listBackupPolicies',
			},
			{
				displayName: 'Subscription ID',
				name: 'subscrId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backup', 'management', 'backupPolicy'],
						operation: [
							'getVeeamAccountDetails',
							'listVeeamAgents',
							'listBackupPolicies',
							'createBackupPolicy',
							'deleteBackupPolicy',
							'assignBackupPolicy',
							'startBackupJob',
							'stopBackupJob',
							'deleteBackupJob',
							'restartBackupAgent',
							'restartManagementAgent',
							'deleteManagementAgent',
							'installBackupAgent',
						],
					},
				},
				default: 0,
				description: 'The ID of the Veeam subscription',
			},
			{
				displayName: 'Backup ID',
				name: 'backupId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backup', 'backupPolicy'],
						operation: [
							'assignBackupPolicy',
							'startBackupJob',
							'stopBackupJob',
							'deleteBackupJob',
							'restartBackupAgent',
						],
					},
				},
				default: 0,
				description: 'The ID of the backup agent',
			},
			{
				displayName: 'Job ID',
				name: 'jobId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backup'],
						operation: [
							'startBackupJob',
							'stopBackupJob',
							'deleteBackupJob',
						],
					},
				},
				default: 0,
				description: 'The ID of the backup job',
			},
			{
				displayName: 'Management ID',
				name: 'managementId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'management'],
						operation: [
							'restartManagementAgent',
							'deleteManagementAgent',
							'installBackupAgent',
						],
					},
				},
				default: 0,
				description: 'The ID of the management agent',
			},
			{
				displayName: 'Policy ID',
				name: 'policyId',
				type: 'number',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['deleteBackupPolicy'],
					},
				},
				default: 0,
				description: 'The ID of the backup policy',
			},
			{
				displayName: 'Policy ID (For Assignment)',
				name: 'assignPolicyId',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backup', 'backupPolicy'],
						operation: ['assignBackupPolicy'],
					},
				},
				default: '',
				description: 'The ID of the policy to assign',
			},
			{
				displayName: 'Policy Name',
				name: 'policyName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '',
				description: 'Name of the backup policy',
			},
			{
				displayName: 'Operating System',
				name: 'os',
				type: 'options',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				options: [
					{
						name: 'Windows',
						value: 'windows',
					},
					{
						name: 'Linux',
						value: 'linux',
					},
				],
				default: 'windows',
				description: 'Operating system for the backup policy',
			},
			{
				displayName: 'Operation Mode',
				name: 'operationMode',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '',
				description: 'Operation mode for the backup policy',
			},
			{
				displayName: 'Backup Mode',
				name: 'backupMode',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '',
				description: 'Backup mode for the policy',
			},
			{
				displayName: 'Description',
				name: 'description',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '',
				description: 'Description of the backup policy (optional)',
			},
			{
				displayName: 'Sources',
				name: 'sources',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '',
				description: 'Sources to backup (optional)',
			},
			{
				displayName: 'Schedule Mode',
				name: 'scheduleMode',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '',
				description: 'Schedule mode for the backup policy (optional)',
			},
			{
				displayName: 'Schedule Day',
				name: 'scheduleDay',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: 'EveryDay',
				description: 'Day schedule for the backup (optional)',
			},
			{
				displayName: 'Schedule Time',
				name: 'scheduleTime',
				type: 'string',
				displayOptions: {
					show: {
						resource: ['veeam', 'backupPolicy'],
						operation: ['createBackupPolicy'],
					},
				},
				default: '00:30',
				description: 'Time schedule for the backup (HH:MM format, optional)',
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
				let body: any = undefined;
				const params: any = {
					login: email,
					crypted_password: cryptedPassword,
					format: format,
				};

				// Determine the endpoint and method based on operation
				switch (operation) {
					case 'listVeeamAccounts':
						endpoint = '/veeam';
						method = 'GET';
						break;
					case 'getVeeamAccountDetails':
						const subscrIdDetails = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/veeam/${subscrIdDetails}`;
						method = 'GET';
						break;
					case 'listVeeamAgents':
						const subscrIdAgents = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/veeam/${subscrIdAgents}/agents`;
						method = 'GET';
						break;
					case 'listBackupPolicies':
						const subscrIdPolicies = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/veeam/${subscrIdPolicies}/backup-policy`;
						method = 'GET';
						break;
					case 'createBackupPolicy':
						const subscrIdCreate = this.getNodeParameter('subscrId', i) as number;
						endpoint = `/veeam/${subscrIdCreate}/backup-policy`;
						method = 'POST';
						const policyName = this.getNodeParameter('policyName', i) as string;
						const os = this.getNodeParameter('os', i) as string;
						const operationMode = this.getNodeParameter('operationMode', i) as string;
						const backupMode = this.getNodeParameter('backupMode', i) as string;
						const description = this.getNodeParameter('description', i, '') as string;
						const sources = this.getNodeParameter('sources', i, '') as string;
						const scheduleMode = this.getNodeParameter('scheduleMode', i, '') as string;
						const scheduleDay = this.getNodeParameter('scheduleDay', i, '') as string;
						const scheduleTime = this.getNodeParameter('scheduleTime', i, '') as string;

						body = {
							name: policyName,
							os: os,
							operation_mode: operationMode,
							backup_mode: backupMode,
						};

						if (description) body.description = description;
						if (sources) body.sources = sources;
						if (scheduleMode) body.schedule_mode = scheduleMode;
						if (scheduleDay) body.day = scheduleDay;
						if (scheduleTime) body.time = scheduleTime;
						break;
					case 'deleteBackupPolicy':
						const subscrIdDeletePolicy = this.getNodeParameter('subscrId', i) as number;
						const policyId = this.getNodeParameter('policyId', i) as number;
						endpoint = `/veeam/${subscrIdDeletePolicy}/backup-policy/${policyId}`;
						method = 'DELETE';
						break;
					case 'assignBackupPolicy':
						const subscrIdAssign = this.getNodeParameter('subscrId', i) as number;
						const backupIdAssign = this.getNodeParameter('backupId', i) as number;
						const assignPolicyId = this.getNodeParameter('assignPolicyId', i) as string;
						endpoint = `/veeam/${subscrIdAssign}/backup/${backupIdAssign}/assign`;
						method = 'POST';
						body = {
							policy_id: assignPolicyId,
						};
						break;
					case 'startBackupJob':
						const subscrIdStart = this.getNodeParameter('subscrId', i) as number;
						const backupIdStart = this.getNodeParameter('backupId', i) as number;
						const jobIdStart = this.getNodeParameter('jobId', i) as number;
						endpoint = `/veeam/${subscrIdStart}/backup/${backupIdStart}/job/${jobIdStart}/start`;
						method = 'PUT';
						break;
					case 'stopBackupJob':
						const subscrIdStop = this.getNodeParameter('subscrId', i) as number;
						const backupIdStop = this.getNodeParameter('backupId', i) as number;
						const jobIdStop = this.getNodeParameter('jobId', i) as number;
						endpoint = `/veeam/${subscrIdStop}/backup/${backupIdStop}/job/${jobIdStop}/stop`;
						method = 'PUT';
						break;
					case 'deleteBackupJob':
						const subscrIdDeleteJob = this.getNodeParameter('subscrId', i) as number;
						const backupIdDeleteJob = this.getNodeParameter('backupId', i) as number;
						const jobIdDeleteJob = this.getNodeParameter('jobId', i) as number;
						endpoint = `/veeam/${subscrIdDeleteJob}/backup/${backupIdDeleteJob}/job/${jobIdDeleteJob}`;
						method = 'DELETE';
						break;
					case 'restartBackupAgent':
						const subscrIdRestartBackup = this.getNodeParameter('subscrId', i) as number;
						const backupIdRestart = this.getNodeParameter('backupId', i) as number;
						endpoint = `/veeam/${subscrIdRestartBackup}/backup/${backupIdRestart}/restart`;
						method = 'PUT';
						break;
					case 'restartManagementAgent':
						const subscrIdRestartMgmt = this.getNodeParameter('subscrId', i) as number;
						const managementIdRestart = this.getNodeParameter('managementId', i) as number;
						endpoint = `/veeam/${subscrIdRestartMgmt}/management/${managementIdRestart}/restart`;
						method = 'PUT';
						break;
					case 'deleteManagementAgent':
						const subscrIdDeleteMgmt = this.getNodeParameter('subscrId', i) as number;
						const managementIdDelete = this.getNodeParameter('managementId', i) as number;
						endpoint = `/veeam/${subscrIdDeleteMgmt}/management/${managementIdDelete}`;
						method = 'DELETE';
						break;
					case 'installBackupAgent':
						const subscrIdInstall = this.getNodeParameter('subscrId', i) as number;
						const managementIdInstall = this.getNodeParameter('managementId', i) as number;
						endpoint = `/veeam/${subscrIdInstall}/management/${managementIdInstall}/backup-agent`;
						method = 'POST';
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

				// Add body for POST/PUT requests
				if ((method === 'POST' || method === 'PUT') && body) {
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