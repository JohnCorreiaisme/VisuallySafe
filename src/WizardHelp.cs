using System;
using System.Collections.Generic;
using System.Linq;

namespace TinyGuard
{
    /// <summary>Everyday help the wizard can say or look up: short tips, and step-by-step answers to the problems older people run into most.
    /// {who} is replaced by the name of the family member the wizard tells people to ask.</summary>
    static class WizardHelp
    {
        public class Topic
        {
            public string Category, Title, Text; public string[] Keys;
            public Topic(string category, string title, string keys, string text) { Category = category; Title = title; Keys = keys.Split('|'); Text = text; }
        }

        static readonly Random rnd = new Random();
        static List<string> bag = new List<string>();

        /// <summary>The next tip, in a shuffled order so it does not repeat until all have been heard.</summary>
        public static string NextTip(string who)
        {
            if (bag.Count == 0) bag = Tips.OrderBy(t => rnd.Next()).ToList();
            string t = bag[0]; bag.RemoveAt(0);
            return t.Replace("{who}", who);
        }

        // lower case, no apostrophes, and the usual short forms spelled one way, so "can't", "cant" and "cannot" all match
        static string Norm(string s)
        {
            s = (s ?? "").ToLowerInvariant().Replace("'", "").Replace("’", "");
            return s.Replace("cannot", "cant").Replace("can not", "cant").Replace(" is not ", " isnt ").Replace(" does not ", " doesnt ").Replace(" will not ", " wont ").Replace(" do not ", " dont ").Replace(" did not ", " didnt ");
        }

        /// <summary>The topic that best matches what the person typed or said, or null.</summary>
        public static Topic Find(string question)
        {
            string q = Norm(question);
            Topic best = null; int bestScore = 0;
            foreach (var t in Topics)
            {
                int score = 0;
                foreach (string raw in t.Keys) { string k = Norm(raw); if (k.Length > 0 && q.Contains(k)) score += 2 + k.Length / 6; }
                if (score > bestScore) { bestScore = score; best = t; }
            }
            return best;
        }

        public static readonly string[] Tips =
        {
            // staying safe from scams
            "A real company will never phone you and say your computer has a virus. If someone does, hang up, and tell {who}.",
            "Never let a stranger take control of your computer, even if they sound kind and say they are from Microsoft or your bank.",
            "If a message says you must act right now, that is a trick. Real banks and offices let you think and call them back.",
            "Never pay anyone with gift cards. No real company or government office will ever ask you to.",
            "If a call or message says a grandchild is in trouble and needs money, hang up. Call your family on the number you already know.",
            "A pop-up with a phone number that says your computer is infected is a scam. Do not call it. Close it, or restart the computer.",
            "You cannot win a prize in a lottery you never entered. Messages that say you did are scams.",
            "If an email says your account is locked, do not click the link. Type your bank's address yourself, or phone them.",
            "Be careful with new friends online who ask for money or gifts. A real friend will not need you to send money.",
            "If something sounds too good to be true, it is. Ask {who} before you reply, click or pay.",
            "Never tell anyone your passwords, your bank card numbers or the six numbers sent to your phone.",
            "A bank will never ask for your full password or card PIN by email, text or phone.",
            "Be careful with links in texts from numbers you do not know. If it is a parcel, check on the shop's own website.",
            "Do not open an email attachment you were not expecting, even if it looks like it came from a friend. Ask them first.",
            "Free programs from pop-up adverts often come with unwanted extras. Ask {who} before you install something.",
            "If you clicked something and now feel worried, that is okay. Close it, tell {who}, and nothing bad has to come of it.",
            // passwords and accounts
            "A good password is a long phrase, like three or four random words together. Long is better than tricky.",
            "Try not to use the same password for everything. If one leaks, all your accounts are at risk.",
            "Write your passwords in a notebook you keep at home, not on a note stuck to the computer.",
            "When a website offers two-step sign-in, say yes. It sends a code to your phone, and keeps thieves out even if they have your password.",
            "A password manager remembers your passwords for you. Ask {who} to help you set one up.",
            // updates, backups and care
            "Let Windows update itself, and restart when it asks. Updates close the holes criminals use.",
            "Keep copies of your favourite photos on a USB stick or in an online album, in case this computer ever breaks.",
            "A restart fixes a surprising number of problems. When in doubt, save your work and restart.",
            "When you finish for the day, use Shut down from the Start menu, not the power button on the computer.",
            "Keep drinks away from the keyboard, and the computer in a place with air around it so it does not overheat.",
            "A laptop likes to be plugged in when its battery runs low. Do not let it go completely flat too often.",
            "Dust inside a computer makes it hot and slow. Ask {who} to blow it out once a year.",
            // everyday how-to
            "To undo a mistake, hold Ctrl and press Z. It takes back the last thing you did.",
            "To copy something, hold Ctrl and press C. To paste it somewhere else, hold Ctrl and press V.",
            "Save your work often. Hold Ctrl and press S, and you will not lose it if the computer freezes.",
            "If you cannot find a file, click the Start button and just start typing its name. Windows will search for it.",
            "Your downloaded files go into a folder called Downloads. Open File Explorer and look on the left side.",
            "If you delete something by mistake, open the Recycle Bin on the Desktop. Right-click the file and choose Restore.",
            "To take a picture of your screen to show a family member, hold the Windows key and Shift, then press S.",
            "To switch between open windows, hold Alt and press Tab.",
            "If a window disappears, look at the bar along the bottom of the screen. Click its little picture to bring it back.",
            "You can make everything bigger. Hold the Windows key and press the plus key to zoom in, and Windows and Escape to stop.",
            "To make the writing bigger everywhere, ask {who} to open Settings and look for Text size under Accessibility.",
            "Hold Ctrl and turn the mouse wheel to make the writing on a web page bigger or smaller.",
            "If the mouse pointer is hard to see, ask {who} to make it bigger in the Settings.",
            "In a web page, hold Ctrl and press F to search for a word on the page.",
            "If you type in capital letters by mistake, press the Caps Lock key once.",
            "The little speaker by the clock changes the volume. The keyboard may have volume keys too.",
            "To lock your computer when you step away, hold the Windows key and press L.",
            "Double-click means two quick clicks. If it is hard, ask {who} to slow the double-click speed in the Settings.",
            "Right-clicking an item shows a list of things you can do with it.",
            "Before you remove a USB stick, click its name in File Explorer and choose Eject.",
            // internet and email
            "If the internet stops working, restart the little box from your internet company. Unplug it for thirty seconds, then plug it back in.",
            "Check the Wi-Fi symbol by the clock. If it has a cross or an aeroplane, ask {who} to help turn it on.",
            "A website with a padlock beside its address is private, but a padlock does not mean the site is honest. Be careful with money.",
            "When you shop online, a credit card gives you more protection than other ways to pay.",
            "Look at the sender's real email address, not just the name. Scammers copy names.",
            "Before you click a link, move the mouse over it. The real address appears at the bottom of the window.",
            "Be careful on public Wi-Fi in cafes and hotels. Do not do your banking there.",
            "Video calls with family are lovely. If the picture or sound does not work, check that the camera and microphone are allowed.",
            "A word you do not know in an email or message? You can ask me, or ask {who}.",
            // calm and kind
            "There is no such thing as a silly question. You can ask me anything, any time.",
            "You cannot break the computer by clicking in the wrong place. If you are unsure, stop and ask.",
            "Take a break every half an hour. Look out of the window, stretch, and rest your eyes.",
            "Have a glass of water. Your computer will wait.",
            "If a screen looks different after an update, do not worry. Everything is still there. Ask me and I will help you find it.",
            "Everyone finds computers confusing sometimes, even the people who make them.",
            "If you are stuck, press the I need help button when I talk to you, and {who} will be told.",
            "I check your computer every Monday and Thursday, and I keep Windows' protection up to date.",
            "The little boxes on your icons are my notes. Green and a tick means I checked it and it is safe.",
            "A yellow box on an icon means it looks a little odd. Do not open it until {who} has had a look.",
            "A red box means danger. Do not open it, and tell {who}.",
            "You can click me and ask a question, or press the microphone button and speak.",
            "You can drag me wherever you like. Let go and I will drop back onto the taskbar."
        };

        public static Topic[] Topics { get { return WizardTopics.All; } }
    }
}
