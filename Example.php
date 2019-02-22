<?php

class Example
{
    /**
     * @param User $user
     * @return string
     */
    protected function createRefreshTokenForUser(User $user): string
    {
        $data = serialize([
            'user_id' => $user->id,
            'expire' => Carbon::now()->addMonth(self::REFRESH_TOKEN_LIFETIME)
        ]);
        $iv = openssl_random_pseudo_bytes(self::IV_LENGTH);
        $token = openssl_encrypt($data, self::CIPHER_REFRESH_TOKEN, env('JWT_SECRET'), OPENSSL_RAW_DATA, $iv);
        $token = base64_encode($iv . $token);

        $this->userRepository->updateByArray($user, ['refresh_token' => $token]);

        return $token;
    }

    /**
     * @param Request $request
     * @return array
     * @throws AccessDeniedHttpException
     */
    public function token(Request $request): array
    {
        $inputData = $request->input('refresh_token');

        if ($inputData === null) {
            throw new AccessDeniedHttpException(__("exception.token.invalid"));
        }

        $token = base64_decode($inputData);
        $iv = substr($token, 0, self::IV_LENGTH); // get IV
        $token = str_replace($iv, '', $token); // delete IV from input string

        $data = openssl_decrypt($token, self::CIPHER_REFRESH_TOKEN, env('JWT_SECRET'), OPENSSL_RAW_DATA, $iv);

        if ($data === false) {
            throw new AccessDeniedHttpException(__("exception.token.invalid"));
        }

        $data = unserialize($data);

        if ($data['expire'] < Carbon::now()) {
            throw new AccessDeniedHttpException(__("exception.token.expired"));
        }

        $user = $this->userRepository->whereFirst(['id' => $data['user_id']]);

        if ($inputData !== $user->refresh_token) {
            throw new AccessDeniedHttpException(__("exception.token.invalid"));
        }

        $newAccessToken = JWTAuth::fromUser($user);
        $newRefreshToken = $this->createRefreshTokenForUser($user);

        return $this->responseWithInfoAboutUsers($user, $newAccessToken, $newRefreshToken);
    }
}