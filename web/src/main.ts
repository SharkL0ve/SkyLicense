import { createApp } from 'vue'
import { createPinia } from 'pinia'
import 'element-plus/theme-chalk/dark/css-vars.css'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'
import App from './App.vue'
import router from './router'
import { initTheme } from './utils/theme'
import './styles/global.scss'

initTheme()

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.mount('#app')
