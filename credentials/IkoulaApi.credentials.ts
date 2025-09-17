import {
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class IkoulaApi implements ICredentialType {
	name = 'ikoulaApi';
	displayName = 'Ikoula API';
	documentationUrl = 'https://api.ikoula.com/docs';
	description = 'Use your Ikoula account credentials. The password will be automatically encrypted using RSA when making API calls. Developed by Ascenzia - www.ascenzia.fr';
	properties: INodeProperties[] = [
		{
			displayName: 'Email',
			name: 'email',
			type: 'string',
			placeholder: 'your-email@example.com',
			default: '',
			required: true,
			description: 'Your Ikoula account email address',
		},
		{
			displayName: 'Password',
			name: 'password',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'Your Ikoula account password (will be encrypted automatically)',
		},
		{
			displayName: 'API URL',
			name: 'apiUrl',
			type: 'string',
			default: 'https://api.ikoula.com',
			required: true,
			description: 'Ikoula API base URL',
		},
	];
}