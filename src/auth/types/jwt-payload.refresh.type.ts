import { jwtPayload }  from '.';



export type jwtPayloadWithRefreshToken= jwtPayload & {refreshToken:string}