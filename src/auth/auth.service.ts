import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Request } from 'express';
import { sign } from 'jsonwebtoken';
import { Model } from 'mongoose';
import { User } from 'src/users/model/users.model';
import { JwtPayload } from './models/jwt-paylod.model';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User')
    private readonly userModel: Model<User>,
  ) {}

  public async createAccessToken(userId: string): Promise<string> {
    return sign({ userId }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });
  }

  public async validateUser({ userId }: JwtPayload): Promise<User> {
    const user = await this.userModel.findOne({ _id: userId });

    if (!user) {
      throw new UnauthorizedException('User not fount.');
    }

    return user;
  }

  private static jwtExtractor(request: Request): string {
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      throw new BadRequestException('Bad request.');
    }

    const [, token] = authHeader.split(' ');

    return token;
  }

  public returnJWTExtractor(): (request: Request) => string {
    return AuthService.jwtExtractor;
  }
}
