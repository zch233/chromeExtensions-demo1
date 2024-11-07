const { createApp, ref, h, nextTick } = Vue
const publicKey = {}
let smCryptoRequest = {}

chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
    const time = details.requestHeaders.find(v => v.name.toLowerCase() === 'x-data-time')?.value
    if (time) {
        chrome.devtools.inspectedWindow.eval('window.smCryptoRequest', (result, isException) => {
            if (isException) {
                console.error('inspectedWindow:', isException);
            } else {
                smCryptoRequest[time] = result[time]?.data || null
            }
        });
    }
}, { urls: ["<all_urls>"] }, ['requestHeaders']);

createApp({
    setup() {
        const list = ref([]);
        const detailRefs = []
        chrome.devtools.network.onRequestFinished.addListener((context) => {
            const getHeader = (key, data) => (data || context.response).headers.find(v => v.name.toLowerCase() === key.toLowerCase())?.value;
            context.getContent((body) => {
                if (getHeader('content-type') === 'application/json') {
                    const requestUrl = context.request.url
                    const origin = requestUrl.split('/').slice(0, 4).join('/')
                    let requestData = smCryptoRequest?.[getHeader('x-data-time', context.request)] || null
                    let responseData = null;
                    try {
                        responseData = JSON.parse(body);
                        const isPublic = requestUrl.includes('/gupo-crypto/crypto/get-public-key')
                        if (isPublic) {
                            publicKey[origin] = responseData.data.public_key;
                        }
                        list.value.push({
                            url: requestUrl.replace(origin, '').split('?')[0],
                            status: `${context.response.status}/${responseData.code}`,
                            requestParams: context.request.queryString,
                            requestData: requestData,
                            responseData: {
                                ...responseData,
                                data: responseData?.data && ((isPublic || getHeader('x-is-safety') !== '1') ? responseData.data : decryptResponse(responseData.data, getHeader('x-data-time'), publicKey[origin])),
                            }
                        })
                    } catch (err) {
                        console.warn('bodyParse:', err);
                        list.value.push({
                            url: requestUrl.replace(origin, '').split('?')[0],
                            status: '🤐',
                            responseData: { message: '别展开了，解析不了' },
                        });
                    }
                }
            });
        });
        const clear = () => {
            list.value = []
            smCryptoRequest = {}
        }
        const toggleDetail = (e, v, i) => {
            if (e.target.open) {
                nextTick(() => {
                    ['requestParams', 'requestData', 'responseData'].map(item => {
                        if (detailRefs?.[i].querySelector(`.${item}El`) && !v[`${item}Viewer`]) {
                            v[`${item}Viewer`] = new LunaObjectViewer(detailRefs?.[i].querySelector(`.${item}El`), {
                                unenumerable: true,
                                accessGetter: true,
                            });
                            v[`${item}Viewer`].set(v[item] ? JSON.parse(JSON.stringify(v[item])) : { message: 'empty' });
                        }
                    })
                });
            }
        }
        const copy = (contentText) => {
            _copy(typeof contentText === 'string' ? contentText : JSON.stringify(contentText))
        }
        return () => h(
            'div', { id: 'gm_networks_tools' },
            [
                h('div', { id: 'gm_networks_tools_header' }, [h('p', {}, [h('span', {}, 'Network-是否灰度'), h('input', { type: 'checkbox', value: 'isGray', switch: true, onChange: (e) => setHeaderGray(e.target.checked) })]), h('span', { onClick: clear }, '🈚')]),
                h('div', { id: 'gm_networks_tools_content' },
                    list.value.map((item, index) => h('div', { key: index }, h('details', { onToggle: (event) => toggleDetail(event, item, index), ref: el => detailRefs[index] = el }, [
                        h('summary', {}, `【${item.status}】${item.url}`),
                        item.requestParams && h('div', { class: 'detailItem' }, [
                            h('p', { style: 'color: #000;' }, [h('span', {}, 'Request[params]'), h('i', { onClick: () => copy(item.requestParams) }, '✍')]),
                            h('div', { class: 'requestParamsEl' }, 'loading...'),
                        ]),
                        item.requestData && h('div', { class: 'detailItem' }, [
                            h('p', { style: 'color: #000;' }, [h('span', {}, 'Request[data]'), h('i', { onClick: () => copy(item.requestData) }, '✍')]),
                            h('div', { class: 'requestDataEl' }, 'loading...'),
                        ]),
                        item.responseData && h('div', { class: 'detailItem' }, [
                            h('p', {}, [h('span', {}, 'Response[data]'), h('i', { onClick: () => copy(item.responseData) }, '✍')]),
                            h('div', { class: 'responseDataEl' }, 'loading...'),
                        ]),
                    ])))),
            ]
        )
    }
}).mount('#gm_networks')

const setHeaderGray = (enable) => {
    chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: [1]
    }, () => {
        chrome.declarativeNetRequest.updateSessionRules({
            addRules: [
                {
                    "id": 1,
                    "priority": 1,
                    "action": {
                        "type": "modifyHeaders",
                        "requestHeaders": [
                            { "header": "x1-gp-color", "operation": "set", "value": enable ? "gray" : "" },
                        ]
                    },
                    "condition": {
                        "urlFilter": "*://*/*",
                        "resourceTypes": ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other"]
                    }
                }
            ],
        }, () => {
            if (chrome.runtime.lastError) {
                console.error("Error updating rules:", chrome.runtime.lastError);
            } else {
                console.info("Rules updated successfully.");
                setTimeout(() => {
                    chrome.declarativeNetRequest.getSessionRules(rules => console.log(rules))
                }, 2000)
            }
        });
    });
}

const decryptViaSM4 = ({ data, key }) => sm4.decrypt(data, key, { /*mode: 'sm4-ecb', */ padding: 'pkcs#7' });
const stringToHex = str => str.split('').reduce((res, v, i) => res + str.charCodeAt(i).toString(16), '');
const buildSM4Secret = (key, time) => {
    const MEDIAN = 5;
    const AFT = 1;
    const BEF = -1;
    const FACTOR_2 = 2;
    const FACTOR_1 = 1;
    const KEY_LENGTH = 16;
    const METHOD = parseInt(time.slice(-2, -1)) > 5 ? AFT : BEF; // 方向
    const _offset = parseInt(time.slice(-1));
    const FACTOR = Math.abs(_offset - METHOD) > MEDIAN ? FACTOR_2 : FACTOR_1; // 系数
    const OFFSET = _offset * FACTOR * METHOD; // 偏移量

    const string = (key + time).toLowerCase();
    const md5Hash = MD5(string).toString(); // 自定义的md5函数，需提前定义
    let _key = md5Hash.substr(OFFSET, KEY_LENGTH);
    while (_key.length < KEY_LENGTH) {
        _key += md5Hash.substr(0, KEY_LENGTH - _key.length);
    }
    return _key;
};
const decryptResponse = (data, time, publicKey) => {
    let _data = decryptViaSM4({
        data,
        key: stringToHex(buildSM4Secret(publicKey, time)),
    });
    try {
        _data = JSON.parse(_data);
    } catch (err) {
        // 非 JSON 数据不解析
    }
    return _data;
};

const deselectCurrent = () => {
    const selection = document.getSelection();
    if (!selection.rangeCount) {
        return function () { };
    }
    let active = document.activeElement;

    const ranges = [];
    for (let i = 0; i < selection.rangeCount; i++) {
        ranges.push(selection.getRangeAt(i));
    }

    switch (
    active.tagName.toUpperCase() // .toUpperCase handles XHTML
    ) {
        case 'INPUT':
        case 'TEXTAREA':
            active.blur();
            break;

        default:
            active = null;
            break;
    }

    selection.removeAllRanges();
    return function () {
        selection.type === 'Caret' && selection.removeAllRanges();

        if (!selection.rangeCount) {
            ranges.forEach(function (range) {
                selection.addRange(range);
            });
        }

        active && active.focus();
    };
};

const clipboardToIE11Formatting = {
    'text/plain': 'Text',
    'text/html': 'Url',
    default: 'Text',
};

const defaultMessage = 'Copy to clipboard: #{key}, Enter';

function format(message) {
    const copyKey = `${/mac os x/i.test(navigator.userAgent) ? '⌘' : 'Ctrl'}+C`;
    return message.replaceAll(/#{\s*key\s*}/g, copyKey);
}

function _copy(text, options) {
    const debug = options?.debug || false;
    let message;
    let reselectPrevious;
    let range;
    let selection;
    let mark;
    let success = false;
    if (!options) {
        options = {};
    }
    try {
        reselectPrevious = deselectCurrent();

        range = document.createRange();
        selection = document.getSelection();

        mark = document.createElement('span');
        mark.textContent = text;
        // avoid screen readers from reading out loud the text
        mark.ariaHidden = 'true';
        // reset user styles for span element
        mark.style.all = 'unset';
        // prevents scrolling to the end of the page
        mark.style.position = 'fixed';
        mark.style.top = '0';
        mark.style.clip = 'rect(0, 0, 0, 0)';
        // used to preserve spaces and line breaks
        mark.style.whiteSpace = 'pre';
        // do not inherit user-select (it may be `none`)
        mark.style.webkitUserSelect = 'text';
        mark.style.MozUserSelect = 'text';
        mark.style.msUserSelect = 'text';
        mark.style.userSelect = 'text';
        mark.addEventListener('copy', function (e) {
            e.stopPropagation();
            if (options.format) {
                e.preventDefault();
                if (typeof e.clipboardData === 'undefined') {
                    // IE 11
                    debug && console.warn('unable to use e.clipboardData');
                    debug && console.warn('trying IE specific stuff');
                    window.clipboardData.clearData();
                    const myFormat = clipboardToIE11Formatting[options.format] || clipboardToIE11Formatting.default;
                    window.clipboardData.setData(myFormat, text);
                } else {
                    // all other browsers
                    e.clipboardData.clearData();
                    e.clipboardData.setData(options.format, text);
                }
            }
            if (options.onCopy) {
                e.preventDefault();
                options.onCopy(e.clipboardData);
            }
        });

        document.body.append(mark);

        range.selectNodeContents(mark);
        selection.addRange(range);

        const successful = document.execCommand('copy');
        if (!successful) {
            throw new Error('copy command was unsuccessful');
        }
        success = true;
    } catch (error) {
        debug && console.error('unable to copy using execCommand:', error);
        debug && console.warn('trying IE specific stuff');
        try {
            window.clipboardData.setData(options.format || 'text', text);
            options.onCopy && options.onCopy(window.clipboardData);
            success = true;
        } catch (error) {
            debug && console.error('unable to copy using clipboardData:', error);
            debug && console.error('falling back to prompt');
            message = format('message' in options ? options.message : defaultMessage);
            window.prompt(message, text);
        }
    } finally {
        if (selection) {
            if (typeof selection.removeRange == 'function') {
                selection.removeRange(range);
            } else {
                selection.removeAllRanges();
            }
        }

        if (mark) {
            mark.remove();
        }
        reselectPrevious();
    }

    return success;
}
