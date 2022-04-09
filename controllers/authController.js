const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('./../models/userModel');
const AppError = require('./../utils/appError');
const catchAsync = require('./../utils/catchAsync');
const sendMail = require('../utils/email');

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  /* this will create a new token and send to user, this token is used to access the protected routes */
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  // res/cookie is for client computer res.cookie(title, value , options)
  res.cookie('jwt', token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token, // the token is stores in user conmputer , then the protected routes will use it.(without this tokens other users can't use your personal infos)
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    role: req.body.role,
  });

  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if the email and password are exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }

  // 2) Check the user exist and password is correct
  const user = await User.findOne({ email }).select('+password'); // this will return false or error while there is no user in that given email address

  const passwordCheck = async () =>
    await user.correctPassword(password, user.password); // this fun check the this given password and the pasword in the database is same or not, is same return true or else throw err that means falsy value

  if (!user || !passwordCheck) {
    // if the email or password is not correct throws(send res) 401 error to user
    return next(new AppError('Incorrect email or password', 401));
  }

  // 3) if every thing is okay send token to client
  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  /*
    ~this controller is created to prtoct the private routes
    ~is the none logged in user comes to this private route, 
     this will check there(user computer) is  token(in simple term *Access key*)
     and give permetion to the route 
  */
  // 1) getting token and check of it's there
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
    // checks there is token or not
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    // if there is no token then throw error response to user
    return next(
      new AppError('You are not logged in! please log in to get access', 401)
    );
  }
  // 2) verification token
  // yes! there is a token, but is that the valid token ?
  const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET); // this methode decode the token using our secretCode , and return the decode

  //??? what if the user deleted the profile but not the access key(Token)? Wooooooooo....
  // don't worry we check that
  // 3) Check is user still exists
  const freshUser = await User.findById(decode.id);

  if (!freshUser) {
    return next(
      new AppError('The user belonging to this token does not exist.', 401)
    );
  }

  /*
    token is created based on user id, 
    the verification is done by using id also
    so there is none is related with the password wright..
    now ??? what if the user changed the password and the token is still there ?
    -> don't worry we check we have function to check that too.
  */
  // 4) Check if user changed password after the token was issued
  if (freshUser.changedPasswordAfter(decode.iat)) {
    /* this fun will check the password the passwordChangedAt date in DB and the token issued at date .
       if  passwordChangedAt is greater than decoded.iat return false that means the password channged and the user needs to login using new password*/
    return next(
      new AppError('User recently changed the password! Please log in again.')
    );
  }

  // GRANT ACCESS TO THE PROTECTED ROUTE
  req.user = freshUser;

  // if all is check , this controller give a way to the next controller in the route
  next();
});


// Only for rendered pages, no errors!
exports.isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      // 1) verify token
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );

      // 2) Check if user still exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next();
      }

      // 3) Check if user changed password after the token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next();
      }

      // THERE IS A LOGGED IN USER
      res.locals.user = currentUser;
      return next();
    } catch (err) {
      return next();
    }
  }
  next();
};


exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }

    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email

  const user = await User.findOne({ email: req.body.email });
  console.log('log 1');
  if (!user) {
    return next(new AppError('There is no user with that email address', 404));
  }
  // 2) Generate the random rest token
  const resetToken = user.createPasswordRestToken();

  await user.save({ validateBeforeSave: false });
  // 3) send it to user's email
  console.log('gate way 2');

  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/user/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to : ${resetURL}. \n If you didn't forgot your password , please ignore this email!`;

  try {
    await sendMail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 mins)',
      message,
    });

    res.status(200).json({
      status: 'Success',
      message: 'Token sent to email!',
    });
  } catch (error) {
    user.passwordRestToken = undefined;
    user.passwordRestExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return new AppError(
      'there was a error sending the email. Try again later!',
      500
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }

  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // get user from collection
  const user = await User.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(req.body.passwordCurrent, user.password)))
    return next(new AppError('Your current password is wrong', 401));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();

  createSendToken(user, 200, res);
});
