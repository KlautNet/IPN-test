import express, { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';
import dotenv from 'dotenv';
import morgan from 'morgan';

dotenv.config();


const app = express();
const port = 3000;

// Middleware to verify IPN signature
const verifyIPNMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const copecartSignature = req.headers['x-copecart-signature'] as string;
    const sharedSecret = process.env.SHARED_SECRET as string || "";

    // Assuming your IPN message is in the request body
    const message = JSON.stringify(req.body);

    const generatedSignature = crypto
        .createHmac('sha256', sharedSecret)
        .update(message)
        .digest('base64');

    if (copecartSignature === generatedSignature) {
        // IPN message is verified
        next();
    } else {
      console.log("Unauthorized")
        res.status(401).send('Unauthorized');
    }
};

app.use(express.json()); // Parse JSON request bodies
app.use(morgan("dev"));

// Apply the middleware to a specific route
app.post('/ipn', verifyIPNMiddleware, (_: Request, res: Response) => {
    // Process the verified IPN message
    console.log("Verified successfully")
    res.status(200).send('IPN verified and processed successfully');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
