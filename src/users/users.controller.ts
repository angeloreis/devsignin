import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { SigninDto } from './dto/signin.dto';
import { SignUpDto } from './dto/signup.dto';
import { User } from './model/users.model';
import { SignInResponse, UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  public async signup(@Body() signupDto: SignUpDto): Promise<User> {
    return this.usersService.signup(signupDto);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  public async signin(@Body() signinDto: SigninDto): Promise<SignInResponse> {
    return this.usersService.signin(signinDto);
  }

  @Get()
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  public async findAll(): Promise<User[]> {
    return this.usersService.findAll();
  }
}
