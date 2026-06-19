import { Schema, model } from 'mongoose';
import { REFRESH_TOKEN_TTL } from '#config';

const refreshTokenSchema = new Schema(
  {
    token: {
      type: String,
      required: true,
      unique: true
    },
    userId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'User'
    },
    expireAt: {
      type: Date,
      default: () => new Date(Date.now() + REFRESH_TOKEN_TTL * 1000)
    }
  },
  {
    timestamps: true
  }
);

// Creates a TTL (Time-To-Live) Index. Document will be removed automatically after <REFRESH_TOKEN_TTL> seconds.
refreshTokenSchema.index({ createdAt: 1 }, { expireAfterSeconds: REFRESH_TOKEN_TTL });

export default model('RefreshToken', refreshTokenSchema);
