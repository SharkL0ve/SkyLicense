package cn.sky.skylicense.web.controller;

import cn.sky.skylicense.web.aop.OpLog;
import cn.sky.skylicense.web.dto.request.BanRequest;
import cn.sky.skylicense.web.dto.response.ApiResponse;
import cn.sky.skylicense.web.dto.response.PageResult;
import cn.sky.skylicense.web.entity.BanRecord;
import cn.sky.skylicense.web.service.BanService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Validated
@RestController
@RequestMapping("/api/bans")
public class BanController {

    private final BanService banService;

    public BanController(BanService banService) {
        this.banService = banService;
    }

    @OpLog(action = "CREATE_BAN", target = "ban")
    @PostMapping
    public ApiResponse<BanRecord> create(@Valid @RequestBody BanRequest request) {
        BanRecord record = banService.createBan(request);
        return ApiResponse.ok("封禁成功", record);
    }

    @GetMapping
    public ApiResponse<PageResult<BanRecord>> list(
            @RequestParam(required = false) @Size(max = 4)
            @Pattern(regexp = "^$|(?i:IP|HWID|QQ|CODE)$") String type,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        return ApiResponse.ok(banService.listBans(type, page, pageSize));
    }

    @GetMapping("/program/{programId}")
    public ApiResponse<PageResult<BanRecord>> listByProgram(
            @PathVariable long programId,
            @RequestParam(defaultValue = "1") @Min(1) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(200) int pageSize) {
        return ApiResponse.ok(banService.listBansByProgram(programId, page, pageSize));
    }

    @OpLog(action = "DELETE_BAN", target = "ban")
    @DeleteMapping("/{id}")
    public ApiResponse<Void> delete(@PathVariable long id) {
        banService.deleteBan(id);
        return ApiResponse.ok("解除封禁成功", null);
    }
}
