use std::sync::Arc;
use anyhow::Result;
use reqwest::Client;
use serde_json::{Map, Value};
use teloxide::dispatching::{Dispatcher, HandlerExt, UpdateFilterExt};
use teloxide::error_handlers::LoggingErrorHandler;
use teloxide::payloads::{EditMessageTextSetters, SendMessageSetters};
use teloxide::prelude::{Requester, RequesterExt};
use teloxide::prelude::Update;
use teloxide::types::{InputFile, Message, Recipient};
use teloxide::{Bot, dispatching::DefaultKey, dptree, utils::command::BotCommands};
use url::Url;

mod config;

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "These commands are supported:", parse_with="split")]
enum Command{
    #[command(description = "start bot")]
    Start,
    #[command(description = "detect phishing site")]
    Detect(String),
}

struct MainBot{
    pub dispatcher: Dispatcher<Arc<Bot>, anyhow::Error, DefaultKey>,
    pub tg: Arc<Bot>,
}
impl MainBot {
    async fn new(config: Arc<config::Config>) -> Result<Self> {
        let tg = Arc::new(
            Bot::new(
                config.telegram_bot_token.clone()
            )
        );
        let _ = tg.clone().parse_mode(teloxide::types::ParseMode::MarkdownV2);
        let _ = tg.set_my_commands(Command::bot_commands());
        let handler = dptree::entry()
            .branch(
                Update::filter_message()
                    .filter_command::<Command>()
                    .endpoint(handle_command),
            ).filter(
                |message: Message, config: Arc<config::Config>|{
                    true
                }
            );
        let dispatcher = Dispatcher::builder(tg.clone(), handler)
            .dependencies(dptree::deps![config.clone()])
            .error_handler(LoggingErrorHandler::with_custom_text(
                "an error has occurred in the dispatcher",
            ))
            .build();
        Ok(MainBot{
            dispatcher,
            tg: tg.clone(),
        })
    }
     pub fn spawn(
        mut self,
    ) -> (
        tokio::task::JoinHandle<()>,
        teloxide::dispatching::ShutdownToken,
    ) {
        let shutdown_token = self.dispatcher.shutdown_token();
        (
            tokio::spawn(async move { self.dispatcher.dispatch().await }),
            shutdown_token,
        )
    }
}
async fn handle_command(
    message: Message,
    bot: Arc<Bot>,
    command: Command,
    config: Arc<config::Config>
) -> Result<()> {
    match command {
        Command::Start => {
            let text = "\
                ✅ <b>Добро пожаловать в бота для обнаружения фишинговых страниц AiTM!</b>\n\n\
                ✨ <i>Как пользоваться:</i>\n\
                • Введите <code>/detect url</code>, где <code>url</code> — это ссылка на сайт, который нужно просканировать.\n\
                ℹ Бот проверит сайт на наличие признаков фишинга и сообщит результаты."
                .to_string();
            
            bot.send_message(message.chat.id, text)
                .parse_mode(teloxide::types::ParseMode::Html)
                .await?;
        }
        Command::Detect(url) => {
            if let Ok(url_obj) = Url::parse(&url) {
                if let Some(host_str) = url_obj.host() {
                    let msg = bot.send_message(message.chat.id, "⏳ <b>Начинаю сканирование...</b>".to_string())
                        .parse_mode(teloxide::types::ParseMode::Html)
                        .await?;
                    bot.send_chat_action(message.chat.id, teloxide::types::ChatAction::Typing).await?;
                    
                    let client = Client::new();
                    let json_data: Map<String, Value> = client
                        .post(format!("http://{}/api/detect/{}", config.detector_address, host_str))
                        .send()
                        .await?
                        .json()
                        .await?;

                    
                    let mut detects_count = 0;
                    let mut msg_text = String::from("\n");
                    
                    for (name, val) in json_data.iter() {
                        let (label, detected) = match name.as_str() {
                            "url_structure" => ("🔗 Подозрительная cтруктура URL", val["status"] == "detected"),
                            "tls_data" => ("🔒 Подозрительные TLS сертификаты", val["status"] == "detected"),
                            "domain_data" => ("🌐 Подозрительное время жизни домена", val["status"] == "detected"),
                            "main_page" => ("📄 Отсутствие главной страницы", val["status"] == "detected"),
                            _ => continue,
                        };
                        
                        msg_text.push_str(&format!("{}: {}\n", label, if detected { "⚠ <b>Обнаружено</b> " } else { "✅ Не обнаружено " }));
                        
                        if detected {
                            detects_count += 1;
                        }
                    }
                    
                    let percent = (detects_count * 100) / json_data.keys().count();
                    let result_text = format!(
                        "\
                        📊 <b>Результаты сканирования:</b> {}%\n\n{}
                        ",
                        percent, msg_text
                    );
                    
                    bot.edit_message_text(message.chat.id, msg.id, result_text)
                        .parse_mode(teloxide::types::ParseMode::Html)
                        .await?;
                    
                    return Ok(());
                }
                bot.send_message(message.chat.id, "❌ <b>Ошибка:</b> Некорректная структура URL")
                    .parse_mode(teloxide::types::ParseMode::Html)
                    .await?;
            }
            bot.send_message(message.chat.id, "❌ <b>Ошибка:</b> Некорректная структура URL")
                .parse_mode(teloxide::types::ParseMode::Html)
                .await?;
        }
    }
    Ok(())
}



#[tokio::main]
async fn main()-> Result<()>{
    let config = Arc::new(config::read_config());
    env_logger::init();
    std::env::set_var("RUST_LOG", "info");
    let bot = MainBot::new(config.clone()).await?;
    let (bot_handle, _) = bot.spawn();
    bot_handle.await?;

    Ok(())
}
