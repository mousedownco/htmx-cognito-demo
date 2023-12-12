import {Amplify} from 'aws-amplify'
import {
    autoSignIn,
    confirmSignUp,
    type ConfirmSignUpInput,
    fetchAuthSession,
    signIn,
    type SignInInput,
    signOut,
    signUp
} from 'aws-amplify/auth'

// if (window.appConfig) {
    console.log('configuring Amplify...')
    Amplify.configure({
        Auth: {
            Cognito: {
                userPoolId: appConfig.userPoolId,
                userPoolClientId: appConfig.userPoolWebClientId
            }
        }
    })
// }

export function configAuth(appConf: any) {
    console.log('configuring Amplify...')
    Amplify.configure({
        Auth: {
            Cognito: {
                userPoolId: appConf.userPoolId,
                userPoolClientId: appConf.userPoolWebClientId
            }
        }
    })
}

/**
 * @see https://docs.amplify.aws/javascript/build-a-backend/auth/enable-sign-up/
 */
type SignUpParams = {
    email: string
    password: string
}

export async function handleSignUp({email, password}: SignUpParams) {
    try {
        const {isSignUpComplete, userId, nextStep} = await signUp({
            username: email,
            password,
            options: {
                userAttributes: {
                    email,
                },
                autoSignIn: true
            }
        })
        console.log('userId:', userId)
        console.log('nextStep:', nextStep)
        return userId
    } catch (error) {
        console.log('error signing up:', error)
    }
}

export async function handleSignUpConfirmation({username, confirmationCode}: ConfirmSignUpInput) {
    try {
        const {isSignUpComplete, nextStep} = await confirmSignUp({username, confirmationCode})
        console.log('isSignUpComplete:', isSignUpComplete)
    } catch (error) {
        console.log('error confirming sign up:', error)
    }
}

export async function handleAutoSignIn() {
    try {
        const user = await autoSignIn()
        console.log('user:', user)
    } catch (error) {
        console.log('error signing in:', error)
    }
}

export async function handleSignIn({username, password}: SignInInput) {
    try {
        console.log('username:', username)
        console.log('signing in...')
        const {isSignedIn, nextStep} = await signIn({username, password})
        console.log('nestStep:', nextStep)
    } catch (error) {
        console.log('error signing in:', error)
    }
}

export async function handleSignOut() {
    try {
        await signOut()
        console.log('signed out')
        window.location.href = '/'
    } catch (error) {
        console.log('error signing out:', error)
    }
}

export async function currentAuthToken() {
    try {
        const session = await fetchAuthSession()
        // console.log('session:', session?.tokens?.idToken?.toString() as string)
        return session?.tokens?.idToken?.toString() as string
    } catch (error) {
        console.log('error getting current session:', error)
    }
}

// https://docs.amplify.aws/javascript/build-a-backend/auth/manage-user-session/

(window as any).configAuth = configAuth;
(window as any).handleSignUp = handleSignUp;
(window as any).handleSignUpConfirmation = handleSignUpConfirmation;
(window as any).handleSignIn = handleSignIn;
(window as any).currentAuthToken = currentAuthToken;
(window as any).handleSignOut = handleSignOut;