import dotenv from 'dotenv';

dotenv.config({
  path: process.env.NODE_ENV === 'development' ? '.env.development' : '.env'
});

interface Config {
  port: number;
  rpcUrl: string;
  privateKey: string;
  contractAddress: string;
  domain: number;
  dvtSecret: string;
}

const config: Config = {
  port: Number(process.env.PORT) || 80,
  rpcUrl: process.env.RPC || '',
  privateKey: process.env.KEY || '',
  contractAddress: process.env.ADD || '',
  domain: Number(process.env.DOMAIN) || 0,
  dvtSecret: process.env.DVT_SECRET || '',
};

const validateConfig = () => {
  const requiredFields: (keyof Config)[] = ['rpcUrl', 'privateKey', 'contractAddress', 'dvtSecret'];
  for (const field of requiredFields) {
    if (!config[field]) {
      throw new Error(`Missing required configuration: ${field}`);
    }
  }
};

export const getConfig = () => {
  validateConfig();
  return config;
};
