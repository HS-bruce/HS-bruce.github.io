(() => {
  'use strict';

  const cryptoObj = window.crypto || window.msCrypto;
  const storage = window.localStorage;

  const storageName = 'hexo-blog-encrypt:#' + window.location.pathname;

// As we can't detect the wrong password with AES-CBC,
// so adding an empty div and check it when decrption.
const knownPrefix = "<hbe-prefix></hbe-prefix>";

  const mainElement = document.getElementById('hexo-blog-encrypt');
  const wrongPassMessage = mainElement.dataset['wpm'];
  const wrongHashMessage = mainElement.dataset['whm'];
  const dataElement = mainElement.getElementsByTagName('script')['hbeData'];
  const encryptedData = dataElement.innerText;
  const HmacDigist = dataElement.dataset['hmacdigest'];
  // If the plugin version is updated but the blog is not regenerated (e.g. caching), the legacy fixed salt value is used.
  const keySalt = dataElement.dataset['keysalt'] ? hexToArray(dataElement.dataset['keysalt']) : textToArray('hexo-blog-encrypt的作者们都是大帅比!');
  const ivSalt = dataElement.dataset['ivsalt'] ? hexToArray(dataElement.dataset['ivsalt']) : textToArray('hexo-blog-encrypt是地表最强Hexo加密插件!');

  function hexToArray(s) {
    return new Uint8Array(s.match(/[\da-f]{2}/gi).map((h => {
      return parseInt(h, 16);
    })));
  }

  function textToArray(s) {
    var i = s.length;
    var n = 0;
    var ba = new Array()

    for (var j = 0; j < i;) {
      var c = s.codePointAt(j);
      if (c < 128) {
        ba[n++] = c;
        j++;
      } else if ((c > 127) && (c < 2048)) {
        ba[n++] = (c >> 6) | 192;
        ba[n++] = (c & 63) | 128;
        j++;
      } else if ((c > 2047) && (c < 65536)) {
        ba[n++] = (c >> 12) | 224;
        ba[n++] = ((c >> 6) & 63) | 128;
        ba[n++] = (c & 63) | 128;
        j++;
      } else {
        ba[n++] = (c >> 18) | 240;
        ba[n++] = ((c >> 12) & 63) | 128;
        ba[n++] = ((c >> 6) & 63) | 128;
        ba[n++] = (c & 63) | 128;
        j += 2;
      }
    }
    return new Uint8Array(ba);
  }

  function arrayBufferToHex(arrayBuffer) {
    if (typeof arrayBuffer !== 'object' || arrayBuffer === null || typeof arrayBuffer.byteLength !== 'number') {
      throw new TypeError('Expected input to be an ArrayBuffer')
    }

    var view = new Uint8Array(arrayBuffer)
    var result = ''
    var value

    for (var i = 0; i < view.length; i++) {
      value = view[i].toString(16)
      result += (value.length === 1 ? '0' + value : value)
    }

    return result
  }

  async function getExecutableScript(oldElem) {
    let out = document.createElement('script');
    const attList = ['type', 'text', 'src', 'crossorigin', 'defer', 'referrerpolicy'];
    attList.forEach((att) => {
      if (oldElem[att])
        out[att] = oldElem[att];
    })

    return out;
  }

  async function convertHTMLToElement(content) {
    let out = document.createElement('div');
    out.innerHTML = content;
    out.querySelectorAll('script').forEach(async (elem) => {
      elem.replaceWith(await getExecutableScript(elem));
    });

    return out;
  }

  function getKeyMaterial(password) {
    let encoder = new TextEncoder();
    return cryptoObj.subtle.importKey(
      'raw',
      encoder.encode(password),
      {
        'name': 'PBKDF2',
      },
      false,
      [
        'deriveKey',
        'deriveBits',
      ]
    );
  }

  function getHmacKey(keyMaterial) {
    return cryptoObj.subtle.deriveKey({
      'name': 'PBKDF2',
      'hash': 'SHA-256',
      'salt': keySalt.buffer,
      'iterations': 1024
    }, keyMaterial, {
      'name': 'HMAC',
      'hash': 'SHA-256',
      'length': 256,
    }, true, [
      'verify',
    ]);
  }

  function getDecryptKey(keyMaterial) {
    return cryptoObj.subtle.deriveKey({
      'name': 'PBKDF2',
      'hash': 'SHA-256',
      'salt': keySalt.buffer,
      'iterations': 1024,
    }, keyMaterial, {
      'name': 'AES-CBC',
      'length': 256,
    }, true, [
      'decrypt',
    ]);
  }

  function getIv(keyMaterial) {
    return cryptoObj.subtle.deriveBits({
      'name': 'PBKDF2',
      'hash': 'SHA-256',
      'salt': ivSalt.buffer,
      'iterations': 512,
    }, keyMaterial, 16 * 8);
  }

  async function verifyContent(key, content) {
    const encoder = new TextEncoder();
    const encoded = encoder.encode(content);

    let signature = hexToArray(HmacDigist);

    const result = await cryptoObj.subtle.verify({
      'name': 'HMAC',
      'hash': 'SHA-256',
    }, key, signature, encoded);
    console.log(`Verification result: ${result}`);
    if (!result) {
      alert(wrongHashMessage);
      console.log(`${wrongHashMessage}, got `, signature, ` but proved wrong.`);
    }
    return result;
  }

  async function decrypt(decryptKey, iv, hmacKey, isSendMsg = true) {
    let typedArray = hexToArray(encryptedData);

    const result = await cryptoObj.subtle.decrypt({
      'name': 'AES-CBC',
      'iv': iv,
    }, decryptKey, typedArray.buffer).then(async (result) => {
      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);

      // check the prefix, if not then we can sure here is wrong password.
      if (!decoded.startsWith(knownPrefix)) {
        throw "Decode successfully but not start with KnownPrefix.";
      }

      // 创建提交按钮和加密按钮的容器
      const buttonContainer = document.createElement('div');
      buttonContainer.style.marginTop = '10px';
      buttonContainer.style.display = 'flex';
      buttonContainer.style.gap = '10px';

      const hideButton = document.createElement('button');
      hideButton.textContent = 'Encrypt again';
      hideButton.type = 'button';
      hideButton.classList.add("hbe-button");
      hideButton.addEventListener('click', () => {
        window.localStorage.removeItem(storageName);
        window.location.reload();
      });

      document.getElementById('hexo-blog-encrypt').style.display = 'inline';
      document.getElementById('hexo-blog-encrypt').innerHTML = '';
      document.getElementById('hexo-blog-encrypt').appendChild(await convertHTMLToElement(decoded));
      document.getElementById('hexo-blog-encrypt').appendChild(buttonContainer);
      buttonContainer.appendChild(hideButton);

      // support html5 lazyload functionality.
      document.querySelectorAll('img').forEach((elem) => {
        if (elem.getAttribute("data-src") && !elem.src) {
          elem.src = elem.getAttribute('data-src');
        }
      });

      // support theme-next refresh
      window.NexT && NexT.boot && typeof NexT.boot.refresh === 'function' && NexT.boot.refresh();

      // TOC part
      var tocDiv = document.getElementById("toc-div");
      if (tocDiv) {
        tocDiv.style.display = 'inline';
      }

      var tocDivs = document.getElementsByClassName('toc-div-class');
      if (tocDivs && tocDivs.length > 0) {
        for (var idx = 0; idx < tocDivs.length; idx++) {
          tocDivs[idx].style.display = 'inline';
        }
      }
      
      // trigger event
      var event = new Event('hexo-blog-decrypt');
      window.dispatchEvent(event);

      return await verifyContent(hmacKey, decoded);
    }).catch((e) => {
      if (isSendMsg) {
        alert(wrongPassMessage);
      }
      console.log(e);
      return false;
    });

    return result;
  }

  function hbeLoader() {
    const oldStorageData = JSON.parse(storage.getItem(storageName));

    if (oldStorageData) {
      console.log(`Password got from localStorage(${storageName}): `, oldStorageData);

      const sIv = hexToArray(oldStorageData.iv).buffer;
      const sDk = oldStorageData.dk;
      const sHmk = oldStorageData.hmk;

      cryptoObj.subtle.importKey('jwk', sDk, {
        'name': 'AES-CBC',
        'length': 256,
      }, true, [
        'decrypt',
      ]).then((dkCK) => {
        cryptoObj.subtle.importKey('jwk', sHmk, {
          'name': 'HMAC',
          'hash': 'SHA-256',
          'length': 256,
        }, true, [
          'verify',
        ]).then((hmkCK) => {
          decrypt(dkCK, sIv, hmkCK).then((result) => {
            if (!result) {
              storage.removeItem(storageName);
            }
          });
        });
      });
    }

    mainElement.addEventListener('keydown', async (event) => {
      if (event.isComposing || event.keyCode === 13) {
        const password = document.getElementById('hbePass').value;
        const keyMaterial = await getKeyMaterial(password);
        const hmacKey = await getHmacKey(keyMaterial);
        const decryptKey = await getDecryptKey(keyMaterial);
        const iv = await getIv(keyMaterial);

        decrypt(decryptKey, iv, hmacKey).then((result) => {
          console.log(`Decrypt result: ${result}`);
          if (result) {
            cryptoObj.subtle.exportKey('jwk', decryptKey).then((dk) => {
              cryptoObj.subtle.exportKey('jwk', hmacKey).then((hmk) => {
                const newStorageData = {
                  'dk': dk,
                  'iv': arrayBufferToHex(iv),
                  'hmk': hmk,
                };
                storage.setItem(storageName, JSON.stringify(newStorageData));
              });
            });
          }
        });
      }
    });

    // 修改样式部分
    const passwordInput = document.getElementById('hbePass');
    const originalContainer = document.getElementById('hexo-blog-encrypt');
    
    // 创建新的表单容器
    const formContainer = document.createElement('div');
    formContainer.style.cssText = `
      display: flex;
      justify-content: center;
      align-items: center;
      margin: 20px auto;
      padding: 20px;
      background: #f5f5f5;
      border-radius: 8px;
    `;

    // 设置输入框样式
    passwordInput.style.cssText = `
      padding: 8px 12px;
      border: 1px solid #ddd;
      border-radius: 4px;
      font-size: 14px;
      outline: none;
      transition: all 0.3s;
      width: 200px;
      height: 36px;
      margin: 0;
      box-sizing: border-box;
      background: white;
    `;

    // 添加提交按钮
    const submitButton = document.createElement('button');
    submitButton.textContent = '提交';
    submitButton.type = 'button';
    submitButton.classList.add("hbe-button");
    
    // 设置按钮样式
    submitButton.style.cssText = `
      margin-left: 10px;
      padding: 8px 20px;
      background-color: #4CAF50;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
      height: 36px;
      transition: all 0.3s;
    `;

    // 设置按钮悬停效果
    submitButton.addEventListener('mouseover', () => {
      submitButton.style.backgroundColor = '#45a049';
    });
    submitButton.addEventListener('mouseout', () => {
      submitButton.style.backgroundColor = '#4CAF50';
    });

    // 输入框焦点效果
    passwordInput.addEventListener('focus', () => {
      passwordInput.style.borderColor = '#4CAF50';
      passwordInput.style.boxShadow = '0 0 5px rgba(76, 175, 80, 0.2)';
    });

    passwordInput.addEventListener('blur', () => {
      passwordInput.style.borderColor = '#ddd';
      passwordInput.style.boxShadow = 'none';
    });

    // 修改DOM结构
    const wrapper = document.createElement('div');
    wrapper.style.cssText = `
      width: 100%;
      display: flex;
      justify-content: center;
    `;
    
    // 保持原始输入框在原位
    const inputParent = passwordInput.parentElement;
    formContainer.appendChild(passwordInput);
    formContainer.appendChild(submitButton);
    wrapper.appendChild(formContainer);
    
    // 插入新容器
    inputParent.appendChild(wrapper);

    // 添加提交按钮的点击事件
    submitButton.addEventListener('click', async () => {
      const password = document.getElementById('hbePass').value;
      const keyMaterial = await getKeyMaterial(password);
      const hmacKey = await getHmacKey(keyMaterial);
      const decryptKey = await getDecryptKey(keyMaterial);
      const iv = await getIv(keyMaterial);

      decrypt(decryptKey, iv, hmacKey).then((result) => {
        console.log(`Decrypt result: ${result}`);
        if (result) {
          cryptoObj.subtle.exportKey('jwk', decryptKey).then((dk) => {
            cryptoObj.subtle.exportKey('jwk', hmacKey).then((hmk) => {
              const newStorageData = {
                'dk': dk,
                'iv': arrayBufferToHex(iv),
                'hmk': hmk,
              };
              storage.setItem(storageName, JSON.stringify(newStorageData));
            });
          });
        }
      });
    });
  }

  hbeLoader();

})();
