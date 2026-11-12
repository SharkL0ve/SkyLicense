package cn.sky.skylicense.web.dto.response;

import cn.sky.skylicense.web.entity.WebUser;

public record AuthSessionResponse(WebUser user, String csrfToken) {
}
