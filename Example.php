<?php

class Example
{
    /**
     * @param User $user
     * @param array $credentials
     * @return string
     */
    protected function createRefreshTokenForUser(User $user, array $credentials): string
    {
        $data = serialize([
            'user_id' => $user->id,
            'expire' => $this->getTokenExpireTime($credentials)
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
    public function updateToken(Request $request): array
    {
        $refreshToken = $request->input('refresh_token');

        if ($refreshToken === null) {
            throw new AccessDeniedHttpException(__("exception.token.invalid"));
        }

        $token = base64_decode($refreshToken);
        $iv = substr($token, 0, self::IV_LENGTH); // get IV
        $token = str_replace($iv, '', $token); // delete IV from input string

        $data = openssl_decrypt($token, self::CIPHER_REFRESH_TOKEN, env('JWT_SECRET'), OPENSSL_RAW_DATA, $iv);

        $data = unserialize($data);

        if ($data['expire'] < Carbon::now()) {
            throw new AccessDeniedHttpException(__("exception.token.expired"));
        }

        $user = $this->userRepository->whereFirst(['id' => $data['user_id']]);

        if ($refreshToken !== $user->refresh_token) {
            throw new AccessDeniedHttpException(__("exception.token.invalid"));
        }

        $newAccessToken = JWTAuth::fromUser($user);
        $newRefreshToken = $this->createRefreshTokenForUser($user, $data);

        return $this->responseWithInfoAboutUsers($user, $newAccessToken, $newRefreshToken);
    }
}