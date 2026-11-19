namespace TinyGuard
{
    /// <summary>Step-by-step answers for the most common problems. They are what the wizard says when no AI is available, and what he looks up first when one is.
    /// Each answer has a calm opening, numbered steps, and a closing line. {who} becomes the name of the family member to ask.</summary>
    static class WizardTopics
    {
        static WizardHelp.Topic T(string cat, string title, string keys, string text) { return new WizardHelp.Topic(cat, title, keys, text); }

        public static readonly WizardHelp.Topic[] All =
        {
            // =============================================================== computer problems
            T("Computer problems", "My program is frozen", "frozen|freeze|stuck|not responding|hung|won't close|wont close|unresponsive|crashed",
              "Don't worry. A frozen program is very common, and it almost never harms anything.\n" +
              "Step 1: Wait for one full minute. Sometimes the program is only busy thinking.\n" +
              "Step 2: Still stuck? Hold down the Ctrl, Alt and Delete keys together, all at once.\n" +
              "Step 3: On the blue screen that appears, click Task Manager.\n" +
              "Step 4: In the list, click the program that is stuck. It often says Not responding beside it.\n" +
              "Step 5: Click End task at the bottom right. The program closes, and you can open it again.\n" +
              "If nothing on the screen moves at all, hold the power button for five seconds until the computer switches off, wait a moment, and switch it on again.\n" +
              "If it keeps happening, tell {who}."),
            T("Computer problems", "The computer is slow", "slow|sluggish|takes forever|taking ages|lag|laggy|slowly",
              "A slow computer can usually be helped with a few easy things.\n" +
              "Step 1: Save what you are doing. Hold Ctrl and press S.\n" +
              "Step 2: Click the Start button, click the power button, and choose Restart. This fixes most slow problems.\n" +
              "Step 3: When it comes back, open only the programs you need. Lots of web pages open at once slows everything down.\n" +
              "Step 4: Close windows you finished with, by clicking the X at the top right.\n" +
              "Step 5: Leave the computer plugged in and switched on for a little while after a restart. Windows is often updating in the background.\n" +
              "If it is still slow after all that, ask {who} to take a look. It may need more free space, or a clean-up."),
            T("Computer problems", "The screen is black or blank", "black screen|blank screen|screen is off|no picture|screen dark|nothing on screen|monitor|screen went black|display",
              "A dark screen is usually something simple.\n" +
              "Step 1: Move the mouse and press the space bar. The computer may only be asleep.\n" +
              "Step 2: Look for a small light on the screen or the computer. No light means no power, so check the plugs.\n" +
              "Step 3: Push every cable in firmly, at both ends. The one from the screen to the computer matters most.\n" +
              "Step 4: On a laptop, press the brightness-up key. It has a small sun on it, usually along the top row. Also plug in the charger, because the battery may be flat.\n" +
              "Step 5: Hold the power button for five seconds to switch off, wait ten seconds, then switch on again.\n" +
              "If the screen is still dark, tell {who}. Your files are almost certainly safe."),
            T("Computer problems", "The computer will not turn on", "won't turn on|wont turn on|will not turn on|doesn't turn on|doesnt turn on|dead|no power|won't start|wont start|won't switch on|wont switch on",
              "Let's check the simple things first.\n" +
              "Step 1: Check the power cable is pushed in firmly at the computer and at the wall.\n" +
              "Step 2: Check the wall socket is switched on. Try plugging in a lamp to see if the socket works.\n" +
              "Step 3: If it plugs into a power strip, check that strip has its switch on.\n" +
              "Step 4: On a laptop, plug in the charger and wait ten minutes. The battery may be completely flat. Then press the power button.\n" +
              "Step 5: Press and hold the power button for a few seconds.\n" +
              "If nothing at all happens, ask {who} to check it. It may be the charger or the cable."),
            T("Computer problems", "The computer restarted by itself", "restarted by itself|restarted on its own|keeps restarting|shut down by itself|turned itself off|rebooted|restarts itself|switched itself off",
              "This can be perfectly normal, or it can mean something needs attention.\n" +
              "Windows sometimes restarts after an update. If that happened overnight, you do not need to do anything.\n" +
              "Step 1: Look in the Start menu for a message about updates. If it asks you to restart, do that and let it finish.\n" +
              "Step 2: Make sure the air holes on the sides and back of the computer are not blocked. A computer that gets too hot will switch itself off.\n" +
              "Step 3: Keep it off a bed or a soft cushion, because they block the air.\n" +
              "If it keeps restarting again and again, or switches off several times a day, tell {who}."),
            T("Computer problems", "I made the writing bigger", "bigger|too small|can't read|cant read|hard to read|zoom|magnify|enlarge|text size|font|tiny writing|small writing|make it larger",
              "You can make things as big as you need, and it is easy.\n" +
              "To zoom in quickly on anything: hold the Windows key and press the plus key. Press it again to zoom in more. Hold the Windows key and press Escape to turn it off.\n" +
              "On a web page: hold the Ctrl key and turn the mouse wheel forward to make the writing bigger, and backward to make it smaller. Ctrl and zero puts it back to normal.\n" +
              "To make the writing bigger everywhere: Step 1, click Start and then Settings. Step 2, click Accessibility, or Ease of Access on older versions. Step 3, click Text size, and slide it to the right until it is easy to read.\n" +
              "If that is tricky, ask {who} to do it for you once, and it will stay that way."),
            T("Computer problems", "I cannot hear anything", "no sound|can't hear|cant hear|no audio|volume|too quiet|muted|mute|speaker|sound not working|can't hear anything",
              "Let's find the sound.\n" +
              "Step 1: Look by the clock for a little speaker picture. If it has a cross or a line through it, click it to un-mute.\n" +
              "Step 2: Click the speaker and slide the volume bar to the right.\n" +
              "Step 3: Check the speakers are switched on and plugged in, and that their own volume knob is turned up.\n" +
              "Step 4: If you use headphones, check they are pushed in all the way. Take them out to hear the speakers.\n" +
              "Step 5: Check the video or program has its own volume. Videos often have a small speaker button in the corner.\n" +
              "Step 6: Restart the computer.\n" +
              "If there is still no sound, tell {who}."),
            T("Computer problems", "The mouse or keyboard is not working", "mouse not working|keyboard not working|mouse|keyboard|cursor|pointer|touchpad|won't type|wont type|can't type|cant type|mouse won't move|mouse wont move",
              "Don't worry. This is usually fixed in a minute.\n" +
              "Step 1: If it has a cable, unplug it and plug it back in firmly. Try a different USB socket on the computer.\n" +
              "Step 2: If it is wireless, change the batteries and check the little plug-in receiver is pushed in.\n" +
              "Step 3: On a laptop with a touchpad, check you have not switched it off. Some laptops have a key with a touchpad picture on it. Ask {who} which one.\n" +
              "Step 4: Restart the computer. If the mouse will not move, press the Windows key on the keyboard, use the arrow keys to reach the power button, and press Enter.\n" +
              "Step 5: Try the mouse or keyboard on another computer if you can.\n" +
              "If it still does not work, it may need replacing. Ask {who} to help."),
            T("Computer problems", "I lost a window", "lost window|window disappeared|window is gone|where did it go|window off screen|can't see the window|cant see the window|missing window|disappeared",
              "Your window is almost certainly still there.\n" +
              "Step 1: Look at the bar along the bottom of the screen. Each open program has a small picture there. Click the picture for your program.\n" +
              "Step 2: Or hold the Alt key and press Tab. Keep Alt held and press Tab again until the window you want is highlighted, then let go.\n" +
              "Step 3: If it is half off the side of the screen, click on it, then hold the Windows key and press the up arrow. That makes it fill the screen.\n" +
              "Step 4: Still lost? Hold the Windows key and press the letter D to show the Desktop, then press the same again to bring windows back.\n" +
              "Nothing you were working on is lost."),
            T("Computer problems", "The computer is full", "full|no space|out of space|disk space|storage|c drive|not enough room|low on space|running out",
              "Your computer's storage is nearly full. That can make it slow and stop updates.\n" +
              "Step 1: Empty the Recycle Bin. Right-click it on the Desktop and choose Empty Recycle Bin.\n" +
              "Step 2: Look in your Downloads folder. Open File Explorer, click Downloads, and delete things you no longer need by clicking them and pressing Delete.\n" +
              "Step 3: Photos and videos take the most room. Ask {who} to help you copy them to a USB stick or an online album, then clear some from the computer.\n" +
              "Please do not delete files you do not recognise, because some are needed by Windows or your programs.\n" +
              "If you are not sure, ask {who} to help you tidy up."),
            T("Computer problems", "I deleted something by mistake", "deleted|delete by mistake|lost a file|lost the file|lost my document|lost a document|lost a photo|missing file|lost my file|lost file|gone missing|can't find my file|cant find my file|where is my file|recycle|recover|undelete|accidentally deleted|deleted my",
              "Take a breath. Deleted files go to a safe place first.\n" +
              "Step 1: Find the Recycle Bin on your Desktop. It looks like a little bin. Double-click it.\n" +
              "Step 2: Look for your file in the list. Files are shown with their names.\n" +
              "Step 3: Right-click the file and choose Restore. It goes back to where it was.\n" +
              "If you cannot see it there, click Start and type part of the file's name to search. Files you downloaded are usually in the Downloads folder.\n" +
              "If it is still missing, tell {who} and do not save anything new until they look. That gives the best chance of getting it back."),
            T("Computer problems", "The printer does not work", "printer|printing|won't print|wont print|print|ink|paper jam|paper",
              "Printers can be fussy, but these steps solve most problems.\n" +
              "Step 1: Check the printer is switched on, and has paper and ink. Look for a blinking light or a message on its little screen.\n" +
              "Step 2: Check the cable is pushed in at both ends. If it is a wireless printer, check it is on the same Wi-Fi as your computer.\n" +
              "Step 3: Switch the printer off, wait ten seconds, and switch it on again.\n" +
              "Step 4: If paper is jammed, switch off, and gently pull the paper out the way it came. Never pull hard.\n" +
              "Step 5: Try printing again. Hold Ctrl and press P, check the right printer is chosen, and click Print.\n" +
              "If it still will not print, ask {who}."),
            T("Computer problems", "How do I turn it off properly", "turn off|shut down|shutdown|switch off|power off|how do i stop|turn it off|turn off the computer|switch it off",
              "Turning off properly keeps everything safe.\n" +
              "Step 1: Save your work. Hold Ctrl and press S, and close your programs.\n" +
              "Step 2: Click the Start button, the Windows picture at the bottom of the screen.\n" +
              "Step 3: Click the power button, then choose Shut down.\n" +
              "Step 4: Wait until the screen goes completely dark and the lights go out.\n" +
              "Step 5: Only then, if you like, switch off at the wall.\n" +
              "Please do not hold the power button to turn it off, unless the computer is frozen."),
            T("Computer problems", "The battery runs out quickly", "battery|charge|charging|plugged in|flat|doesn't hold charge|doesnt hold charge|runs out",
              "A few simple habits help the battery last longer.\n" +
              "Step 1: Plug in the charger, and check it is pushed in at both ends. A small light usually shows it is charging.\n" +
              "Step 2: Turn the screen brightness down a little. A bright screen uses a lot of battery.\n" +
              "Step 3: Close programs and web pages you are not using.\n" +
              "Step 4: Keep the laptop plugged in when you can, and try not to let it go completely flat very often.\n" +
              "If the battery empties in under an hour even when it is old, ask {who}. It may need replacing."),
            T("Computer problems", "The screen is sideways or upside down", "upside down|sideways|rotated|flipped|screen turned|the screen is turned",
              "Don't worry. This can happen by pressing keys by accident, and it is fixable.\n" +
              "Step 1: Hold the Ctrl and Alt keys, and press the up arrow. This puts the screen the right way up on most computers.\n" +
              "Step 2: If that does not work, right-click an empty spot on the Desktop and choose Display settings.\n" +
              "Step 3: Look for Display orientation, and choose Landscape.\n" +
              "If it will not change, ask {who} to help."),
            T("Computer problems", "Something keeps asking me to sign in", "keeps asking|asking me to sign in|keeps asking for password|sign in again|log in again|pin|windows hello",
              "That can be annoying, but it is usually harmless.\n" +
              "Step 1: Type the password or PIN you use to start the computer. Take your time, and check Caps Lock is off.\n" +
              "Step 2: If it is a website, click Forgot password, and follow the steps it gives.\n" +
              "Step 3: Never type your password into a message or a pop-up you did not ask for.\n" +
              "If you cannot remember your computer's password, ask {who} before you try many guesses."),
            T("Computer problems", "The date or time is wrong", "wrong time|wrong date|clock|time is wrong|date is wrong|time zone|wrong day",
              "A wrong clock can stop websites from working, so it is worth fixing.\n" +
              "Step 1: Right-click the time at the bottom right of the screen.\n" +
              "Step 2: Choose Adjust date and time.\n" +
              "Step 3: Switch on Set time automatically, and Set time zone automatically.\n" +
              "Step 4: If it is still wrong, click Change under Set the date and time manually, and type the right time.\n" +
              "Ask {who} if you are unsure."),

            // =============================================================== internet and email
            T("Internet and email", "The internet is not working", "no internet|internet down|internet isnt working|internet is down|internet wont|lost internet|lost my internet|cant get online|wifi isnt|internet not working|can't connect|cant connect|wifi|wi-fi|not connected|offline|network|router|connection",
              "Let's get you back online, step by step.\n" +
              "Step 1: Look at the little Wi-Fi picture by the clock. If it has a cross or a plane on it, click it and turn Wi-Fi on, and make sure Airplane mode is off.\n" +
              "Step 2: Find the box from your internet company, usually with small blinking lights. Unplug its power for thirty full seconds, then plug it back in.\n" +
              "Step 3: Wait two or three minutes for the lights to settle.\n" +
              "Step 4: Restart your computer.\n" +
              "Step 5: Try a web page again.\n" +
              "If the box has a red light, or the internet is still off, call your internet company, or ask {who}. It might be a fault in your area."),
            T("Internet and email", "A web page will not open", "page won't open|page wont open|website won't load|website not loading|web page|site down|can't open website|cant open website|browser|page not loading|won't load|wont load",
              "Let's work out whether it is your computer or the website.\n" +
              "Step 1: Click the circular arrow beside the address to try again.\n" +
              "Step 2: Open a different website, like a news site. If that works, the first site may simply be down. Try it again later.\n" +
              "Step 3: If no websites open, your internet is off. Look at the Wi-Fi picture by the clock, and check the internet box has its lights on.\n" +
              "Step 4: Check you typed the address correctly. One wrong letter will not work.\n" +
              "Step 5: Close the browser and open it again.\n" +
              "Still stuck? Ask {who}."),
            T("Internet and email", "Pop-ups keep appearing", "pop-up|popup|pop up|ads keep|adverts|advertisement|keep appearing|keeps popping|keeps showing|flashing|warning on my screen",
              "A pop-up that says your computer is in danger is an advert or a scam. It is not a real warning from Windows.\n" +
              "Step 1: Do not click anything inside it, not even Close, No or Cancel. Those buttons can be traps.\n" +
              "Step 2: Hold the Alt key and press F4. This closes the window.\n" +
              "Step 3: If it will not close, hold Ctrl, Alt and Delete together, click Task Manager, click your web browser, and press End task.\n" +
              "Step 4: If it still comes back, restart the computer.\n" +
              "Step 5: Do not call any phone number shown on it.\n" +
              "Tell {who}, so they can check the computer is fine."),
            T("Internet and email", "I forgot my password", "forgot password|forgotten password|forgot my password|password reset|reset password|can't log in|cant log in|locked out|can't sign in|cant sign in|lost my password|don't remember my password|dont remember my password",
              "It happens to everyone, and it is easy to fix.\n" +
              "Step 1: On the sign-in page, look for words like Forgot password. Click them.\n" +
              "Step 2: The website will send a link to your email address, or a code to your phone. Wait a minute, and check your Spam folder too.\n" +
              "Step 3: Follow the link, and choose a new password. A good one is three or four unrelated words, like a short sentence.\n" +
              "Step 4: Write it in a notebook you keep at home. Do not stick it on the computer.\n" +
              "Never tell your password to anyone who phones or emails you, even if they say they are your bank.\n" +
              "If you are locked out of the computer itself, ask {who}."),
            T("Internet and email", "Is this email real", "is this email real|email real|suspicious email|strange email|phishing|spam|junk mail|fake email|weird email|odd email|dodgy email",
              "It is wise to check. Here is how to tell.\n" +
              "Step 1: Look at the sender's real email address, not only the name. Scammers use real company names with a strange address.\n" +
              "Step 2: Does it rush you, scare you, or say your account will be closed? That is a warning sign.\n" +
              "Step 3: Does it ask for passwords, bank details, or gift cards? A real company never does.\n" +
              "Step 4: Look for spelling mistakes and odd wording.\n" +
              "Step 5: Do not click links or open attachments you were not expecting.\n" +
              "If you are not sure, do not click anything. Forward it to {who} and ask. Deleting it is always safe."),
            T("Internet and email", "I clicked a bad link", "clicked a link|clicked on a link|clicked the link|clicked something|opened an attachment|opened a file|i clicked|clicked it|opened it by mistake",
              "Stay calm. Many clicks do no harm at all, and you did the right thing by asking.\n" +
              "Step 1: Close the page or the window. Hold Alt and press F4.\n" +
              "Step 2: Do not type any passwords, card numbers or personal details into anything it showed you.\n" +
              "Step 3: Tell {who} right away so they can check the computer.\n" +
              "Step 4: If you did type a password, change it as soon as you can, on the real website.\n" +
              "Step 5: If you shared bank details, phone your bank straight away, on the number on your card.\n" +
              "You can ask me, 'Is my computer okay?' and I will check what Windows' protection says."),
            T("Internet and email", "How do I make a video call", "video call|video chat|zoom|skype|facetime|whatsapp|facebook call|call my family|camera|webcam|talk to my family|see my family",
              "Seeing your family is lovely, and it is easier than it looks.\n" +
              "Step 1: Open the program your family uses, such as WhatsApp, Zoom, Skype or Messenger.\n" +
              "Step 2: Click the person you want to call.\n" +
              "Step 3: Click the camera button, which looks like a little video camera.\n" +
              "Step 4: If they cannot see or hear you, look for the camera and the microphone buttons on the screen, and make sure neither has a line through it.\n" +
              "Step 5: Check nothing is covering the camera lens, and your speakers are on.\n" +
              "Ask {who} to put a shortcut for the call on your Desktop, so it takes only one click."),
            T("Internet and email", "Where did my download go", "download|downloaded|where did it go|saved file|where is it saved|where's my download|wheres my download",
              "Downloaded files go to one place.\n" +
              "Step 1: Click the little yellow folder at the bottom of the screen. That is File Explorer.\n" +
              "Step 2: On the left side, click Downloads.\n" +
              "Step 3: Your newest files are at the top. Double-click one to open it.\n" +
              "In your web browser, you can also hold Ctrl and press J to see a list of downloads.\n" +
              "Only open files you were expecting, and ask {who} if you are not sure."),
            T("Internet and email", "I lost my email", "email gone|emails gone|lost my email|can't find my email|cant find my email|inbox empty|deleted email|spam folder|email disappeared|missing email",
              "Emails are rarely lost, they are just hiding.\n" +
              "Step 1: Look in the Spam or Junk folder, in the list on the left side. Real emails sometimes land there by mistake.\n" +
              "Step 2: Look in the Trash, or Deleted items, folder in the same list.\n" +
              "Step 3: Use the search box at the top, and type the sender's name or a word from the email.\n" +
              "Step 4: Check you are signed in to the right email account. A different account has a different inbox.\n" +
              "If you still cannot find it, ask {who}."),
            T("Internet and email", "How do I send a photo by email", "send a photo|attach a photo|attach|send a picture|email a photo|email picture|share a photo|share photos|send photos",
              "You can send photos to family easily.\n" +
              "Step 1: Open your email and click New message or Write.\n" +
              "Step 2: Type your family member's email address, and a short subject like Photos.\n" +
              "Step 3: Click the paperclip button, which means Attach.\n" +
              "Step 4: Find the photo in Pictures, click it, and click Open.\n" +
              "Step 5: Click Send.\n" +
              "If the photos are very large, send just a few at a time. If it does not work, ask {who} to show you once."),
            T("Internet and email", "My email password stopped working", "email password|password stopped|password not working|password wrong|wrong password|says my password|invalid password",
              "That can happen after the email company makes a change.\n" +
              "Step 1: Type the password again slowly. Check Caps Lock is off, and watch for look-alike letters.\n" +
              "Step 2: Open the email website itself, like gmail.com or outlook.com, and try signing in there.\n" +
              "Step 3: If that fails, click Forgot password and follow the steps to make a new one.\n" +
              "Step 4: After you make a new one, the email program on your computer may ask for it again. Type the new one.\n" +
              "Ask {who} if it does not work, and never give your password to anyone who contacts you."),

            // =============================================================== scams and safety
            T("Scams and safety", "Someone phoned about a virus", "phoned me|called me|phone call|someone called|microsoft called|tech support|support called|they said my computer|virus warning|says i have a virus|you have a virus|rang me|telephone",
              "This is a scam. You did the right thing to ask.\n" +
              "Microsoft, your bank and your internet company do not phone people about viruses.\n" +
              "Step 1: Hang up. You do not have to be polite to a scammer.\n" +
              "Step 2: Do not press any buttons, do not go to any website they tell you, and never let them onto your computer.\n" +
              "Step 3: Do not pay them anything, and never give card numbers or passwords.\n" +
              "Step 4: Tell {who} right away.\n" +
              "If you already let them in, switch the computer off, then phone your bank and {who}. Your bank can help protect your money."),
            T("Scams and safety", "Someone wants gift cards", "gift card|gift cards|itunes card|google play card|steam card|vouchers|bitcoin|wire money|send money|western union|money transfer|crypto",
              "Please do not buy them. This is a scam.\n" +
              "No real company, bank, government office or police officer will ever ask you to pay with gift cards, bitcoin or a money transfer. Only scammers do.\n" +
              "Step 1: Stop. Do not go to the shop, and do not read out any card numbers.\n" +
              "Step 2: Hang up or stop replying.\n" +
              "Step 3: Tell {who}. If you already paid, phone your bank, and tell the gift card company straight away. Sometimes the money can be recovered if you act fast."),
            T("Scams and safety", "My grandchild needs money", "grandson|granddaughter|grandchild|grandkid|relative in trouble|bail|arrested|accident|in jail|needs money urgently|family emergency|my son|my daughter",
              "Please stop and check. This is a very common scam, and it is made to scare you.\n" +
              "Scammers can copy voices, and they often say do not tell anyone.\n" +
              "Step 1: Hang up, however upset the caller sounds.\n" +
              "Step 2: Phone your grandchild, or another family member, on the number you already have, not a new one.\n" +
              "Step 3: Ask a question only they would know, like a pet's name.\n" +
              "Step 4: Do not send money, or buy gift cards, until you have checked.\n" +
              "Step 5: Tell {who}.\n" +
              "A real family member will understand that you checked."),
            T("Scams and safety", "A message says I won something", "won|winner|prize|lottery|sweepstakes|inheritance|million|claim your|congratulations|free gift|selected|you've been chosen|youve been chosen",
              "This is a scam, even if it looks exciting.\n" +
              "You cannot win a prize in something you never entered, and a real prize never asks you to pay a fee first.\n" +
              "Step 1: Do not click the links, and do not reply.\n" +
              "Step 2: Do not give your bank details, your address or any ID.\n" +
              "Step 3: Delete the message.\n" +
              "Step 4: Tell {who} if you are worried, or if you already replied.\n" +
              "If it sounds too good to be true, it is."),
            T("Scams and safety", "My bank wants me to confirm details", "bank|account locked|account suspended|verify your|confirm your account|card blocked|paypal|amazon account|update your payment|your account has|security alert|suspicious activity",
              "Be careful. This is usually a trick to steal your details.\n" +
              "Your real bank never asks for your full password or PIN by email, text or phone.\n" +
              "Step 1: Do not click the link, and do not call the number in the message.\n" +
              "Step 2: Find the phone number on the back of your bank card, and call that number.\n" +
              "Step 3: Or go into the bank in person.\n" +
              "Step 4: Tell {who} if you are not sure.\n" +
              "If you already typed your details, phone your bank straight away and tell them."),
            T("Scams and safety", "A friend online asks for money", "online friend|romance|dating|met online|never met|asks for money|asking me for money|love|sweetheart|facebook friend|stranger",
              "Please be very careful. You are not silly. These scammers are skilled and patient.\n" +
              "If someone you have only met online asks for money, gifts or bank details, it is almost always a scam, even if they seem kind and say they love you.\n" +
              "Step 1: Do not send any money, gift cards or bank details.\n" +
              "Step 2: Ask to video call. Scammers will always find a reason not to.\n" +
              "Step 3: Talk to {who} or a friend you trust, before you do anything.\n" +
              "Step 4: If you have already sent money, tell your bank and {who} straight away."),
            T("Scams and safety", "I think I have a virus", "i have a virus|infected|virus|malware|hacked|hacker|ransomware|my files are locked|ransom|compromised",
              "Let's stay calm and check carefully.\n" +
              "Step 1: Ask me, 'Is my computer okay?' I will look at what Windows' own protection says.\n" +
              "Step 2: Press the Scan my computer button, and Windows will run a scan.\n" +
              "Step 3: Do not click any pop-up that says you are infected, and never call a number shown on the screen. Those are scams.\n" +
              "Step 4: Do not pay anyone, even if a message says your files are locked.\n" +
              "Step 5: If your files are locked and a message asks for money, switch the computer off and call {who}.\n" +
              "Most worries turn out to be nothing, and Windows' protection is working in the background."),
            T("Scams and safety", "Should I trust this website", "trust this website|is this website safe|safe website|website safe|is this site safe|legit|legitimate|genuine|real website|fake website|is this a scam",
              "Here is how to check.\n" +
              "Step 1: Read the address at the top carefully. Scammers copy names with a small change, like an extra letter.\n" +
              "Step 2: Be careful if it is rushed, much too cheap, or has lots of spelling mistakes.\n" +
              "Step 3: Be careful if it only takes payment by gift card, bank transfer or crypto.\n" +
              "Step 4: Search for the shop's name along with the word reviews, and read what other people say.\n" +
              "Step 5: When you pay, use a credit card, which gives more protection than other ways.\n" +
              "If you are not sure, ask {who} before you buy."),
            T("Scams and safety", "Can I let someone fix my computer remotely", "remote access|remote control|teamviewer|anydesk|quick assist|let them in|take control|share my screen|remote help|control my computer",
              "Be careful. Only ever allow it for someone you called yourself and know well.\n" +
              "Step 1: Never allow a stranger who phoned, emailed or messaged you to control your computer. That is how scammers steal money.\n" +
              "Step 2: If {who} needs to help from far away, press the I need help button when I talk to you. I will get the help started the safe way.\n" +
              "Step 3: If someone already has control, switch off the computer and unplug the internet cable.\n" +
              "Step 4: Tell {who}, and phone your bank if you gave any bank details."),
            T("Scams and safety", "Texts about parcels and deliveries", "parcel|package|delivery|royal mail|courier|ups|fedex|dhl|usps|missed delivery|redelivery|customs fee|text message|sms",
              "Be wary. Fake delivery texts are very common.\n" +
              "Step 1: Do not tap the link in the text, even if you are expecting a parcel.\n" +
              "Step 2: Real companies do not ask for small fees by text to redeliver.\n" +
              "Step 3: If you think it could be real, go to the delivery company's own website by typing its address, or use its official app.\n" +
              "Step 4: Delete the text, and tell {who} if you tapped the link or typed any details."),
            T("Scams and safety", "Keeping my passwords safe", "keep passwords safe|good password|strong password|write down password|password manager|reuse password|same password|two step|two-step|2fa|authenticator",
              "Good password habits keep you safe.\n" +
              "Step 1: Use a long password made of three or four unrelated words, like a short sentence. Long is stronger than tricky.\n" +
              "Step 2: Try not to use the same password for everything. If one leaks, all of them are in danger.\n" +
              "Step 3: Write them in a notebook that stays at home. Do not stick them on the computer.\n" +
              "Step 4: When a website offers two-step sign-in, say yes. It texts a code to your phone, and keeps thieves out.\n" +
              "Step 5: Never tell anyone your passwords, or the codes sent to your phone.\n" +
              "Ask {who} to help set up a password manager if you would like."),

            // =============================================================== everyday how-to
            T("Everyday how-to", "How do I copy and paste", "copy and paste|copy paste|how do i copy|how do i paste|ctrl c|ctrl v|cut and paste|copying",
              "Copy and paste saves a lot of typing.\n" +
              "Step 1: Highlight what you want. Click at the start, hold the left mouse button down, drag to the end, and let go. It turns blue or grey.\n" +
              "Step 2: Hold the Ctrl key and press C. That copies it.\n" +
              "Step 3: Click where you want it to go.\n" +
              "Step 4: Hold the Ctrl key and press V. That pastes it.\n" +
              "You can also right-click and choose Copy, then right-click and choose Paste."),
            T("Everyday how-to", "How do I undo", "undo|take it back|i made a mistake|made a mistake|go back|redo|oops",
              "Mistakes are easy to undo.\n" +
              "Step 1: Hold the Ctrl key and press Z. This takes back the last thing you did.\n" +
              "Step 2: Press Z again to take back one step further.\n" +
              "Step 3: If you went too far, hold Ctrl and press Y to put it back.\n" +
              "If you deleted a file, look in the Recycle Bin on the Desktop. I can show you how."),
            T("Everyday how-to", "How do I save a file", "save a file|how do i save|save my work|saving|save as|keep my work|did it save",
              "Saving often means nothing is ever lost.\n" +
              "Step 1: Hold the Ctrl key and press S.\n" +
              "Step 2: If it asks where to save, choose a folder you will remember, like Documents.\n" +
              "Step 3: Type a name you will recognise, like Letter to Anna.\n" +
              "Step 4: Click Save.\n" +
              "After that, pressing Ctrl and S saves your changes in the same place."),
            T("Everyday how-to", "How do I find a file", "find a file|find my file|search for a file|where is my document|find a document|find a photo|find my photos|search|looking for a file|where did i save",
              "Your file is probably easy to find.\n" +
              "Step 1: Click the Start button, the Windows picture at the bottom of the screen.\n" +
              "Step 2: Just start typing the name of the file. Even part of the name will do.\n" +
              "Step 3: Windows lists what it finds. Click the one you want.\n" +
              "Another way: click the yellow folder at the bottom of the screen to open File Explorer, and look in Documents, Pictures and Downloads on the left.\n" +
              "If you remember roughly when you made it, look for Recent files near the top of Quick access."),
            T("Everyday how-to", "How do I take a screenshot", "screenshot|screen shot|picture of my screen|photo of my screen|capture the screen|snip|show you my screen|show my screen",
              "A screenshot lets you show {who} exactly what you see.\n" +
              "Step 1: Hold the Windows key and Shift, and press the letter S.\n" +
              "Step 2: The screen goes a little dark. Click and drag a box around the part you want.\n" +
              "Step 3: It is now copied. Open an email or a document, and hold Ctrl and press V to paste it in.\n" +
              "Step 4: Send it to {who}, with a short note about what is happening."),
            T("Everyday how-to", "How do I print a page", "print a page|how do i print|print this|print my|print out|printing a page|print a letter",
              "Printing is only a few clicks.\n" +
              "Step 1: Make sure the printer is switched on and has paper.\n" +
              "Step 2: Hold the Ctrl key and press P.\n" +
              "Step 3: Check the printer name in the box is the right one.\n" +
              "Step 4: Choose how many copies, and which pages.\n" +
              "Step 5: Click Print."),
            T("Everyday how-to", "How do I change the screen brightness", "brightness|too bright|too dark|dim|bright|eye strain|eyes hurt|glare|screen is hurting",
              "You can make the screen easier on your eyes.\n" +
              "Step 1: On a laptop, look along the top row of keys for a small sun. Press the up sun for brighter and the down sun for dimmer. You may need to hold the Fn key too.\n" +
              "Step 2: On Windows, click the little Wi-Fi and speaker pictures by the clock. There is a brightness slider in the box that opens.\n" +
              "Step 3: In the evening, ask {who} to turn on Night light in Settings, which makes the screen warmer.\n" +
              "Also rest your eyes. Every twenty minutes, look at something far away for twenty seconds."),
            T("Everyday how-to", "How do I connect to Wi-Fi", "connect to wifi|connect to wi-fi|join wifi|wifi password|wi-fi password|new wifi|connect wifi|how do i get online|set up wifi",
              "Connecting is easy once you have the password.\n" +
              "Step 1: Click the Wi-Fi picture by the clock.\n" +
              "Step 2: Click your network's name in the list. If you are at home, it is often printed on the internet box.\n" +
              "Step 3: Click Connect.\n" +
              "Step 4: Type the Wi-Fi password. It is usually on a sticker on the box. Check the capital letters.\n" +
              "Step 5: Click Next, and wait a few seconds.\n" +
              "If it does not work, ask {who}, or phone your internet company."),
            T("Everyday how-to", "How do I install a program", "install|installing|download a program|new program|new app|add a program|software|get a program",
              "Please check with {who} before you install anything. It is the most common way people catch trouble.\n" +
              "Step 1: Only download from the official website of the program, or from the Microsoft Store.\n" +
              "Step 2: Be careful with free versions found through adverts and pop-ups. They often come with unwanted extras.\n" +
              "Step 3: Read each screen of the installer before clicking Next. Untick extra offers.\n" +
              "Step 4: If it asks for permission and you did not start it, click No.\n" +
              "Ask {who} to help if you are not sure."),
            T("Everyday how-to", "How do I update Windows", "update windows|windows update|updates|updating|restart for updates|update available|windows is updating",
              "Updates keep you safe, so they are worth doing.\n" +
              "Step 1: Click Start, then Settings, which looks like a little gear.\n" +
              "Step 2: Click Windows Update.\n" +
              "Step 3: Click Check for updates.\n" +
              "Step 4: Let it finish. It may take a while, and the computer may restart. Please do not switch it off while it says Updating.\n" +
              "Step 5: Leave it plugged in. If you have a laptop, check the charger is in.\n" +
              "I also keep Windows' protection up to date for you, every Monday and Thursday."),
            T("Everyday how-to", "How do I use the Start menu", "start menu|start button|where is start|find programs|find my programs|open a program|how do i open|launch",
              "The Start menu is where everything begins.\n" +
              "Step 1: Click the Windows picture at the bottom of the screen. On some computers it is in the middle, and on others at the left.\n" +
              "Step 2: You will see some of your programs. Click one to open it.\n" +
              "Step 3: To find any program, just start typing its name.\n" +
              "Step 4: The power button inside it switches the computer off or restarts it.\n" +
              "Step 5: Press the Windows key on the keyboard to open it quickly."),
            T("Everyday how-to", "What are those buttons at the top of a window", "minimize|minimise|maximize|maximise|close button|top right corner|x button|three buttons|what does the x do|what do those buttons do",
              "Every window has three buttons at the top right.\n" +
              "The line, or dash, hides the window down to the bar at the bottom. It is not closed, and you can bring it back by clicking its picture there.\n" +
              "The square makes the window fill the screen, or shrink back. Two squares means click to make it smaller.\n" +
              "The X closes the window completely. Save your work first. Hold Ctrl and press S."),
            T("Everyday how-to", "How do I back up my photos", "back up|backup|backing up|photos safe|keep my photos|save my photos|lose my photos|usb stick|memory stick|copy my photos",
              "A backup means a broken computer will not lose your memories.\n" +
              "Step 1: Plug a USB stick into the computer.\n" +
              "Step 2: Click the yellow folder at the bottom of the screen, and click Pictures on the left.\n" +
              "Step 3: Select the photos. Hold Ctrl and press A to select them all.\n" +
              "Step 4: Hold Ctrl and press C to copy.\n" +
              "Step 5: Click the USB stick on the left, and hold Ctrl and press V to paste.\n" +
              "Step 6: When finished, right-click the USB stick name and choose Eject before you pull it out.\n" +
              "Keep the stick in a safe place. Ask {who} about an online album as a second copy."),
            T("Everyday how-to", "How do I talk to the computer", "speak to the computer|talk to the computer|dictate|voice typing|voice|microphone|speak instead of typing|use my voice",
              "You can talk, and I will listen.\n" +
              "Step 1: Click me, and the question window opens. Press the Speak button, and ask your question out loud. Speak clearly, and not too fast.\n" +
              "Step 2: To type with your voice in other programs, click in the box where you want the words, hold the Windows key and press H, and start talking.\n" +
              "Step 3: Check the microphone is plugged in and not muted.\n" +
              "If it cannot hear you, ask {who} to check the microphone."),
            T("Everyday how-to", "How do I use a USB stick", "usb|flash drive|pen drive|memory stick|thumb drive|eject|safely remove",
              "A USB stick is a small way to carry files.\n" +
              "Step 1: Push it firmly into the USB socket on the side or the back of the computer.\n" +
              "Step 2: Click the yellow folder at the bottom of the screen. Your stick appears on the left.\n" +
              "Step 3: Click it to see what is on it. Copy files with Ctrl and C, and paste with Ctrl and V.\n" +
              "Step 4: When you finish, right-click its name and choose Eject.\n" +
              "Step 5: Wait for the message, then pull it out.\n" +
              "Only use sticks from people you trust, because they can carry viruses."),
            T("Everyday how-to", "How do I change the volume", "change the volume|turn up the volume|turn down the volume|louder|quieter|turn it up|turn it down",
              "It is easy to change the volume.\n" +
              "Step 1: Click the small speaker picture by the clock, at the bottom right.\n" +
              "Step 2: Slide the bar right for louder, left for quieter.\n" +
              "Step 3: The keyboard may have volume keys too, often along the top, with pictures of a speaker.\n" +
              "Step 4: Videos have their own small speaker button to check."),
            T("Everyday how-to", "How do I look up something on the internet", "search the internet|google|look something up|search online|how do i search|find information|look it up",
              "Searching is how you find out almost anything.\n" +
              "Step 1: Open your web browser. Click its picture at the bottom of the screen.\n" +
              "Step 2: Click in the long bar at the top.\n" +
              "Step 3: Type what you want to know, like weather tomorrow, and press Enter.\n" +
              "Step 4: A list of results appears. The first few might say Ad. Look further down for ordinary results.\n" +
              "Step 5: Click a result to open it.\n" +
              "Be careful with any site that asks for money or personal details, and ask {who} if you are unsure."),
            T("Everyday how-to", "How do I close a window or program", "close a window|close a program|exit|quit|how do i close|get out of this|close this|close the page",
              "There are a few easy ways.\n" +
              "Step 1: Click the X at the top right of the window.\n" +
              "Step 2: Or hold the Alt key and press F4.\n" +
              "Step 3: If it asks Do you want to save, click Save if you want to keep your work, or Don't save if not.\n" +
              "Step 4: If it will not close, tell me it is frozen, and I will show you how to end it."),
            T("Everyday how-to", "Who do I ask for help", "help|i need help|need some help|who can i ask|can you help|help me|don't know|dont know|confused|what do i do|not sure",
              "I am here to help, so you can ask me anything. There are no silly questions.\n" +
              "Step 1: Type or say your question in the box, and press Ask.\n" +
              "Step 2: Press the Common problems button to see lists of topics, such as frozen programs and scams.\n" +
              "Step 3: If it is something I cannot do, press the I need help button when I talk, and {who} will be told.\n" +
              "You are doing fine.")
        };
    }
}
