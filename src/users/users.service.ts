import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Model } from 'mongoose';
import { AuthService } from 'src/auth/auth.service';
import { SigninDto } from './dto/signin.dto';
import { SignUpDto } from './dto/signup.dto';
import { User } from './model/users.model';

export type SignInResponse = {
  name: string;
  jwtToken: string;
  email: string;
};
@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
    private readonly authService: AuthService,
  ) {}

  public async signup(signUpDto: SignUpDto): Promise<User> {
    const user = new this.usersModel(signUpDto);
    return user.save();
  }

  public async signin(signinDto: SigninDto): Promise<SignInResponse> {
    const user = await this.findByEmail(signinDto.email);
    const match = await this.checkPassword(signinDto.password, user);

    if (!match) {
      throw new NotFoundException('Invalid credentials.');
    }

    const { name, email } = user;

    const jwtToken = await this.authService.createAccessToken(user._id);

    return { name, jwtToken, email };
  }

  public async findAll(): Promise<User[]> {
    return this.usersModel.find();
  }

  private async findByEmail(email: string): Promise<User> {
    const user = await this.usersModel.findOne({ email });

    if (!user) {
      throw new NotFoundException('Email not found.');
    }

    return user;
  }

  private async checkPassword(password, user: User): Promise<boolean> {
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      throw new NotFoundException('Password not found.');
    }

    return match;

    return false;
  }
}
