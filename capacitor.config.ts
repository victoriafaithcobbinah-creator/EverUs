// Capacitor Native Mobile Wrapper Configuration for iOS (Apple) & Android
const config = {
  appId: 'app.everus.couples',
  appName: 'EverUs',
  webDir: 'dist',
  server: {
    androidScheme: 'https',
    iosScheme: 'https',
  },
  plugins: {
    SplashScreen: {
      launchShowDuration: 1500,
      backgroundColor: '#fff5f7',
      showSpinner: false,
    },
    PushNotifications: {
      presentationOptions: ['badge', 'sound', 'alert'],
    },
    LocalNotifications: {
      smallIcon: 'ic_stat_heart',
      iconColor: '#ec4899',
    },
  },
};

export default config;
