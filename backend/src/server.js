import app from './app.js';
import env from './config/env.js';
import connectDatabase from './config/db.js';

try {
	console.log('Connecting to MongoDB...');
	await connectDatabase();
} catch (error) {
	console.error('Failed to connect to MongoDB', error);
	process.exit(1);
}

app.listen(env.port, () => {
	console.log(`Backend listening on port ${env.port}`);
});	
