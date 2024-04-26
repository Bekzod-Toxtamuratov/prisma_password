import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Response } from 'express';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateAuthDto, UpdateAuthDto } from './dto';
import { LoginAuthDto } from './dto/logi-auth.dto';
import { jwtPayload, tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async getTokens(userId: number, email: string): Promise<tokens> {
    const jwtPayload: jwtPayload = {
      sub: userId,
      email: email,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }
  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 7);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken: hashedRefreshToken,
      },
    });
  }
  async signup(createAuthDto: CreateAuthDto, res: Response) {
    const condidate = await this.prismaService.user.findUnique({
      where: {
        email: createAuthDto.email,
      },
    });

    if (condidate) {
      throw new BadRequestException('user already exists!');
    }

    const hashedPassword = await bcrypt.hash(createAuthDto.password, 7);

    const newUser = await this.prismaService.user.create({
      data: {
        name: createAuthDto.name,
        email: createAuthDto.email,
        hashedPassword,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRefreshToken(newUser.id, tokens.refresh_token);

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    return tokens;
  }
  // ********************************************Login******************************************************

  async login(loginauthDto: LoginAuthDto, res: Response) {
    const { email, password } = loginauthDto;
    const auth = await this.prismaService.user.findFirst({ where: { email } });

    if (!auth) {
      throw new BadRequestException('auth not found');
    }
    // if (!auth.is_active) {
    //   throw new BadRequestException('auth is not activate');
    // }

    const passwordIsMatch = await bcrypt.compare(password, auth.hashedPassword);
    if (!passwordIsMatch) {
      throw new BadRequestException('Password do not match');
    }

    console.log('auth', auth);
    const tokens = await this.getTokens(auth.id, auth.email);

    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);

    const oldauth = await this.prismaService.user.findFirst({
      where: {
        id: auth.id,
      },
    });

    if (!oldauth) {
      throw new BadRequestException('auth not Found');
    }

    // const updateauth = await this.prismaService.user.save({
    //   ...checkauth,
    //   hashed_refresh_token: hashed_refresh_token,
    // });
    const updateauth = await this.prismaService.user.update({
      where: {
        id: oldauth.id,
      },
      data: {
        hashedRefreshToken: hashed_refresh_token,
      },
    });

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });
    const responce = {
      message: 'auth logged in',
      auth: updateauth.name,
      auth_email: updateauth.email,
      tokens,
    };

    return responce;
  }

  // *************************************Logout*****************************************************
  async logout(refreshToken: string, res: Response) {
    const authData = await this.jwtService.verify(refreshToken, {
      secret: process.env.REFRESH_TOKEN_KEY,
    });
    if (!authData) {
      throw new ForbiddenException('auth not verified');
    }
    // const checkStuff = await this.prismaService.user.findFirst(where:id: stuffData.id );

    const checkAuth = await this.prismaService.user.findFirst({
      where: {
        id: authData.id,
      },
    });

    if (!checkAuth) {
      throw new BadRequestException('Auth not Found');
    }

    const updatedAuth = await this.prismaService.user.update({
      where: {
        email: checkAuth.email,
      },
      data: {
        hashedRefreshToken: null,
      },
    });

    res.clearCookie('refresh_token');
    const response = {
      message: 'auth logged out successfully',
      auth_hashed_token: updatedAuth.hashedRefreshToken,
    };
    return response;
  }

  // *******************************************************************************************************************

  async refreshToken(AuthId: number, refreshToken: string, res: Response) {
    console.log('refreshToken');
    const decodedToken = await this.jwtService.decode(refreshToken);

    console.log('decoded token', decodedToken);
    if (AuthId !== decodedToken['sub']) {
      throw new BadRequestException('auth not found');
    }
    const auth = await this.prismaService.user.findFirst({
      where: { id: AuthId },
    });

    if (!auth || !auth.hashedRefreshToken) {
      throw new BadRequestException('auth not found');
    }
    const tokenMatch = await bcrypt.compare(
      refreshToken,
      auth.hashedRefreshToken,
    );

    if (!tokenMatch) {
      throw new ForbiddenException('Forbidden');
    }

    const tokens = await this.getTokens(auth.id, auth.email);
    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);

    const checkStuff = await this.prismaService.user.findFirst({
      where: { id: auth.id },
    });
    if (!checkStuff) {
      throw new BadRequestException('auth not Found');
    }
    const updateUser = await this.prismaService.user.update({
      where: { id: auth.id },
      data: {
        hashedRefreshToken: hashed_refresh_token,
      },
    });

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });

    const response = {
      message: 'auth refreshedToken',
      user: updateUser.name,
      tokens,
    };
    return response;
  }

  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
