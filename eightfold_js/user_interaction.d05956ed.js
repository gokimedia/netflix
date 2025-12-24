var localStorageName='efUserInteractionHistory';var maxLocalStorageSize=2500000;function handleCurrentLocalStorageSize(){var currentLocalStorageSize=(window.localStorage.getItem(localStorageName)||'').length;if(currentLocalStorageSize>=maxLocalStorageSize){submitUserInteractionHistory();}}
function reportUserInteraction(event,entityId,domain){var isUserInteractionEnabled=document.getElementById('userInteractionEnabled');if(!isUserInteractionEnabled){return;}
if(window.EF_COOKIE_HANDLER&&window.EF_COOKIE_HANDLER.necessaryOnly){return;}
if(!entityId||!domain){return;}
if(!supportLocalStorage()){return;}
handleCurrentLocalStorageSize();var userInteractionHistory=JSON.parse(window.localStorage.getItem(localStorageName))||[];userInteractionHistory.push({'event_name':event,'entity_id':entityId,'domain':domain});try{window.localStorage.setItem(localStorageName,JSON.stringify(userInteractionHistory));}catch(error){console.error("Cannot Set LocalStorage");}}
function startRecordingUserInteraction(){if(!supportLocalStorage()){return;}
submitUserInteractionHistory();setInterval(submitUserInteractionHistory,20000);}
function submitUserInteractionHistory(){if(!supportLocalStorage()){return;}
var userInteractionHistory=window.localStorage.getItem(localStorageName);if(userInteractionHistory&&userInteractionHistory!=JSON.stringify([])){var userInteractionHistoryList=JSON.parse(userInteractionHistory)
var data={data:userInteractionHistory,domain:userInteractionHistoryList[0].domain};$.post('/api/user_interaction/submit',data);}
window.localStorage.setItem(localStorageName,JSON.stringify([]));}