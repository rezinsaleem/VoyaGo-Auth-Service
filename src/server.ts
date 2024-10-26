import path from 'path';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import 'dotenv/config';
import { Authcontroller } from './controller/authController';

const authController = new Authcontroller()

const PROTO_PATH = path.resolve(__dirname, './protos/auth.proto');
const packageDef = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
});

const grpcObject = grpc.loadPackageDefinition(packageDef) as any;

if (
  !grpcObject.auth ||
  !grpcObject.auth.Auth ||
  !grpcObject.auth.Auth.service
) {
  console.error('Failed to load the User service from the proto file.');
  process.exit(1);
}

const server = new grpc.Server();

server.addService(grpcObject.auth.Auth.service, {
  RefreshToken: authController.refreshToken,
  IsAuthenticated : authController.isAuthenticated,   
});

const SERVER_ADDRESS = process.env.GRPC_SERVER_PORT || '50002';

const Domain =
  process.env.NODE_ENV === 'dev'
    ? process.env.DEV_DOMAIN
    : process.env.PRO_DOMAIN_USER;

server.bindAsync(
  `${Domain}:${SERVER_ADDRESS}`,
  grpc.ServerCredentials.createInsecure(),
  (err, port) => {
    if (err) {
      console.error(`Failed to bind server: ${err}`);
      return;
    }
    console.log(`gRPC server running at ${port}`);
  }
);
