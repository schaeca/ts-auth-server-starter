import { type ErrorRequestHandler } from 'express';

const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  process.env.NODE_ENV !== 'production' && console.log(`\x1b[31m${err.stack}\x1b[0m`);

  let errorMessage = 'Internal server error';
  let statusCode = 500;

  if (err instanceof Error) {
    // check if cause property exists, is an object, and has a 'status' property
    if (err.cause && typeof err.cause === 'object' && 'status' in err.cause) {
      //statusCode = err.cause.status as number --> type cast to include potional code property:
      const {status, code} = err.cause as {status: number; code?: string}
      statusCode = status

      // set the WWW-Authenticate header if the error was caused by an expired access token
      if (code === 'ACCESS_TOKEN_EXPIRED')
        res.setHeader(
          'WWW-Authenticate',
          'Bearer error="token_expired", error_description="The access token expired"'
        );
    }
    errorMessage = err.message;
  }
  res.status(statusCode).json({ error: errorMessage });
};

export default errorHandler;
